package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	dbcrypto "amoon-eclipse/server/internal/crypto"
	"amoon-eclipse/server/internal/email"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type Handler struct {
	db                   *sql.DB
	jwtSecret            string
	enc                  *dbcrypto.FieldEncryptor
	hmac                 *dbcrypto.HmacTokener
	googleClientID       string
	googleClientSecret   string
	facebookAppID        string
	mailer               *email.Sender
}

func NewHandler(db *sql.DB, jwtSecret string, enc *dbcrypto.FieldEncryptor, hmac *dbcrypto.HmacTokener, googleClientID, googleClientSecret, facebookAppID string, mailer *email.Sender) *Handler {
	return &Handler{db: db, jwtSecret: jwtSecret, enc: enc, hmac: hmac, googleClientID: googleClientID, googleClientSecret: googleClientSecret, facebookAppID: facebookAppID, mailer: mailer}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	// Public — no JWT required
	r.Post("/register", h.register)
	r.Post("/login", h.login)
	r.Post("/oauth", h.oauth)
	r.Get("/google/start", h.googleStart)
	r.Get("/google/callback", h.googleCallback)
	r.Post("/forgot-password", h.forgotPassword)
	r.Post("/forgot-username", h.forgotUsername)
	r.Post("/reset-password", h.resetPassword)

	// Protected — JWT required (inline middleware using h.jwtSecret)
	r.Group(func(r chi.Router) {
		r.Use(h.requireAuth)
		r.Post("/register-key", h.registerKey)
		r.Post("/store-encrypted-key", h.storeEncryptedKey)
		r.Get("/encrypted-key", h.getEncryptedKey)
	})
	return r
}

// requireAuth is an inline JWT middleware for auth-sub-routes.
func (h *Handler) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			jsonError(w, "missing token", http.StatusUnauthorized)
			return
		}
		claims, err := VerifyJWT(strings.TrimPrefix(header, "Bearer "), h.jwtSecret)
		if err != nil {
			jsonError(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, ContextKeyUserID, claims.UserID)
		ctx = context.WithValue(ctx, ContextKeyUsername, claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ── Register (email + password) ────────────────────────────────────────────

type registerReq struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"` // Argon2id hash từ client
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)

	// Check username đã tồn tại chưa
	var exists int
	h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users WHERE username=?`, req.Username).Scan(&exists)
	if exists > 0 {
		jsonError(w, "username đã được dùng", http.StatusConflict)
		return
	}

	// Hash password lần 2 phía server (defence in depth — client đã argon2id rồi)
	serverHash, err := HashArgon2id(req.Password)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	var emailEnc, emailToken string
	if req.Email != "" {
		emailEnc, err = h.enc.Encrypt(req.Email)
		if err != nil {
			jsonError(w, "encrypt error", http.StatusInternalServerError)
			return
		}
		emailToken = h.hmac.Token(strings.ToLower(req.Email))
	}

	id := uuid.NewString()
	_, err = h.db.ExecContext(r.Context(),
		`INSERT INTO users(id,username,password_hash,email_enc,email_token) VALUES(?,?,?,?,?)`,
		id, req.Username, serverHash, nullStr(emailEnc), nullStr(emailToken),
	)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	token, _ := SignJWT(id, req.Username, h.jwtSecret)
	jsonOK(w, map[string]any{"token": token, "userId": id, "username": req.Username})
}

// ── Login ──────────────────────────────────────────────────────────────────

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	var id, username, hash string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, username, password_hash FROM users WHERE username=? AND password_hash IS NOT NULL`,
		req.Username,
	).Scan(&id, &username, &hash)
	if err != nil {
		jsonError(w, "sai username hoặc password", http.StatusUnauthorized)
		return
	}

	ok, err := VerifyArgon2id(req.Password, hash)
	if err != nil || !ok {
		jsonError(w, "sai username hoặc password", http.StatusUnauthorized)
		return
	}

	var pubKey string
	h.db.QueryRowContext(r.Context(), `SELECT COALESCE(public_key,'') FROM users WHERE id=?`, id).Scan(&pubKey)

	token, _ := SignJWT(id, username, h.jwtSecret)
	jsonOK(w, map[string]any{"token": token, "userId": id, "username": username, "publicKey": pubKey})
}

// ── OAuth (Google / Facebook) ──────────────────────────────────────────────

type oauthReq struct {
	Provider    string `json:"provider"`    // "google" | "facebook"
	AccessToken string `json:"accessToken"` // token từ client OAuth flow
}

type googleUserInfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Aud   string `json:"aud"` // audience — phải khớp với client ID của app
}

type fbUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (h *Handler) oauth(w http.ResponseWriter, r *http.Request) {
	var req oauthReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	var oauthID, email, name string

	switch req.Provider {
	case "google":
		info, err := fetchGoogle(req.AccessToken, h.googleClientID)
		if err != nil {
			jsonError(w, "google token invalid", http.StatusUnauthorized)
			return
		}
		oauthID, email, name = info.Sub, info.Email, info.Name
	case "facebook":
		info, err := fetchFacebook(req.AccessToken, h.facebookAppID)
		if err != nil {
			jsonError(w, "facebook token invalid", http.StatusUnauthorized)
			return
		}
		oauthID, email, name = info.ID, info.Email, info.Name
	default:
		jsonError(w, "provider không hỗ trợ", http.StatusBadRequest)
		return
	}

	// Tìm user hiện có
	var id, username string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, username FROM users WHERE oauth_provider=? AND oauth_id=?`,
		req.Provider, oauthID,
	).Scan(&id, &username)

	if err == sql.ErrNoRows {
		// Tạo user mới
		id = uuid.NewString()
		username = sanitizeUsername(name) + "_" + id[:6]

		var emailEnc, emailToken string
		if email != "" {
			emailEnc, _ = h.enc.Encrypt(email)
			emailToken = h.hmac.Token(strings.ToLower(email))
		}

		_, err = h.db.ExecContext(r.Context(),
			`INSERT INTO users(id,username,oauth_provider,oauth_id,email_enc,email_token) VALUES(?,?,?,?,?,?)`,
			id, username, req.Provider, oauthID, nullStr(emailEnc), nullStr(emailToken),
		)
		if err != nil {
			jsonError(w, "db error", http.StatusInternalServerError)
			return
		}
	} else if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}

	token, _ := SignJWT(id, username, h.jwtSecret)
	jsonOK(w, map[string]any{"token": token, "userId": id, "username": username})
}

// ── Register Public Key ────────────────────────────────────────────────────

type registerKeyReq struct {
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
}

func (h *Handler) registerKey(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextKeyUserID).(string)

	var req registerKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PublicKey == "" {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	_, err := h.db.ExecContext(r.Context(),
		`UPDATE users SET public_key=?, fingerprint=? WHERE id=?`,
		req.PublicKey, req.Fingerprint, userID,
	)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// ── Helpers ────────────────────────────────────────────────────────────────

// fetchGoogle verify access token + kiểm tra audience nếu có clientID
func fetchGoogle(accessToken, clientID string) (*googleUserInfo, error) {
	resp, err := httpGet("https://www.googleapis.com/oauth2/v3/userinfo?access_token=" + accessToken)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, io.EOF
	}
	var info googleUserInfo
	json.NewDecoder(resp.Body).Decode(&info)
	if info.Sub == "" {
		return nil, io.EOF
	}

	// Verify audience nếu server có cấu hình clientID (chống confused deputy attack)
	if clientID != "" && info.Aud != "" && info.Aud != clientID {
		return nil, fmt.Errorf("google token audience mismatch")
	}
	return &info, nil
}

// fetchFacebook verify token + kiểm tra app ID
func fetchFacebook(accessToken, appID string) (*fbUserInfo, error) {
	url := "https://graph.facebook.com/me?fields=id,name,email&access_token=" + accessToken

	// Nếu có App ID, dùng debug_token để verify chắc chắn hơn
	if appID != "" {
		// App access token format: appID|appSecret — nhưng ở đây ta chỉ verify qua userinfo
		// và check app_id trong response
		debugResp, err := httpGet("https://graph.facebook.com/debug_token?input_token=" + accessToken + "&access_token=" + accessToken)
		if err == nil && debugResp.StatusCode == 200 {
			var debug struct {
				Data struct {
					AppID   string `json:"app_id"`
					IsValid bool   `json:"is_valid"`
				} `json:"data"`
			}
			json.NewDecoder(debugResp.Body).Decode(&debug)
			debugResp.Body.Close()
			if !debug.Data.IsValid || (debug.Data.AppID != "" && debug.Data.AppID != appID) {
				return nil, fmt.Errorf("facebook token invalid or wrong app")
			}
		}
	}

	resp, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, io.EOF
	}
	var info fbUserInfo
	json.NewDecoder(resp.Body).Decode(&info)
	if info.ID == "" {
		return nil, io.EOF
	}
	return &info, nil
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func httpGet(url string) (*http.Response, error) {
	return httpClient.Get(url)
}

func sanitizeUsername(name string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else if c == ' ' {
			b.WriteRune('_')
		}
	}
	s := b.String()
	if len(s) > 20 {
		s = s[:20]
	}
	if s == "" {
		s = "user"
	}
	return s
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type contextKey string

const ContextKeyUserID contextKey = "userID"
const ContextKeyUsername contextKey = "username"

// ── Forgot Password ────────────────────────────────────────────────────────

type forgotReq struct {
	Email string `json:"email"`
}

func (h *Handler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Tìm user qua email token
	token := h.hmac.Token(strings.ToLower(req.Email))
	var id string
	var emailEnc string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, email_enc FROM users WHERE email_token=?`, token,
	).Scan(&id, &emailEnc)

	// Luôn trả 200 dù có tìm thấy hay không (chống email enumeration)
	if err != nil {
		jsonOK(w, map[string]string{"status": "sent"})
		return
	}

	if h.mailer == nil {
		jsonError(w, "email chưa được cấu hình trên server", http.StatusServiceUnavailable)
		return
	}

	// Decrypt email thật
	emailPlain, err := h.enc.Decrypt(emailEnc)
	if err != nil {
		jsonOK(w, map[string]string{"status": "sent"})
		return
	}

	// Tạo OTP 6 số
	otp := genOTP()
	otpHash, err := HashArgon2id(otp)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	expires := time.Now().Add(10 * time.Minute).Unix()
	h.db.ExecContext(r.Context(),
		`UPDATE users SET reset_token=?, reset_expires=? WHERE id=?`,
		otpHash, expires, id,
	)

	if err := h.mailer.SendOTP(emailPlain, otp); err != nil {
		log.Printf("ERROR SendOTP to %s: %v", emailPlain, err)
		jsonError(w, "không gửi được email, thử lại sau", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "sent"})
}

type resetReq struct {
	Email    string `json:"email"`
	OTP      string `json:"otp"`
	Password string `json:"password"` // new password hash
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.OTP == "" || req.Password == "" {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	token := h.hmac.Token(strings.ToLower(req.Email))
	var id, otpHash string
	var expires int64
	err := h.db.QueryRowContext(r.Context(),
		`SELECT id, reset_token, reset_expires FROM users WHERE email_token=? AND reset_token IS NOT NULL`,
		token,
	).Scan(&id, &otpHash, &expires)
	if err != nil {
		jsonError(w, "OTP không hợp lệ hoặc đã hết hạn", http.StatusUnauthorized)
		return
	}

	if time.Now().Unix() > expires {
		jsonError(w, "OTP đã hết hạn", http.StatusUnauthorized)
		return
	}

	ok, _ := VerifyArgon2id(req.OTP, otpHash)
	if !ok {
		jsonError(w, "OTP sai", http.StatusUnauthorized)
		return
	}

	newHash, err := HashArgon2id(req.Password)
	if err != nil {
		jsonError(w, "server error", http.StatusInternalServerError)
		return
	}

	h.db.ExecContext(r.Context(),
		`UPDATE users SET password_hash=?, reset_token=NULL, reset_expires=NULL WHERE id=?`,
		newHash, id,
	)
	jsonOK(w, map[string]string{"status": "ok"})
}

// ── Passphrase-encrypted key backup ───────────────────────────────────────

type storeKeyReq struct {
	EncryptedKey string `json:"encryptedKey"` // JSON: {salt, iv, ciphertext} base64
	KeySalt      string `json:"keySalt"`
}

func (h *Handler) storeEncryptedKey(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextKeyUserID).(string)
	var req storeKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.EncryptedKey == "" {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	h.db.ExecContext(r.Context(),
		`UPDATE users SET encrypted_key=?, key_salt=? WHERE id=?`,
		req.EncryptedKey, req.KeySalt, userID,
	)
	jsonOK(w, map[string]string{"status": "ok"})
}

func (h *Handler) getEncryptedKey(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ContextKeyUserID).(string)
	var encKey, keySalt string
	h.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(encrypted_key,''), COALESCE(key_salt,'') FROM users WHERE id=?`, userID,
	).Scan(&encKey, &keySalt)
	jsonOK(w, map[string]any{"encryptedKey": encKey, "keySalt": keySalt})
}

// ── Google OAuth server-side ───────────────────────────────────────────────

const googleRedirectURI = "https://engine.congmc.com/api/auth/google/callback"

func (h *Handler) googleStart(w http.ResponseWriter, r *http.Request) {
	params := url.Values{
		"client_id":     {h.googleClientID},
		"redirect_uri":  {googleRedirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"access_type":   {"offline"},
	}
	http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?"+params.Encode(), http.StatusFound)
}

func (h *Handler) googleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "amoon-eclipse:///auth?error=cancelled", http.StatusFound)
		return
	}

	// Exchange code for token
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {code},
		"client_id":     {h.googleClientID},
		"client_secret": {h.googleClientSecret},
		"redirect_uri":  {googleRedirectURI},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		http.Redirect(w, r, "amoon-eclipse:///auth?error=token_exchange", http.StatusFound)
		return
	}
	defer resp.Body.Close()
	var tokenRes struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tokenRes)
	if tokenRes.AccessToken == "" {
		http.Redirect(w, r, "amoon-eclipse:///auth?error=no_token", http.StatusFound)
		return
	}

	// Get user info
	req, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenRes.AccessToken)
	infoResp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Redirect(w, r, "amoon-eclipse:///auth?error=userinfo", http.StatusFound)
		return
	}
	defer infoResp.Body.Close()
	var info struct {
		Sub   string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	json.NewDecoder(infoResp.Body).Decode(&info)
	if info.Sub == "" {
		http.Redirect(w, r, "amoon-eclipse:///auth?error=no_user", http.StatusFound)
		return
	}

	// Find or create user
	var userID, username string
	err = h.db.QueryRowContext(r.Context(),
		`SELECT id, username FROM users WHERE oauth_provider='google' AND oauth_id=?`, info.Sub,
	).Scan(&userID, &username)

	if err == sql.ErrNoRows {
		userID = uuid.New().String()
		username = strings.ReplaceAll(strings.ToLower(info.Name), " ", "_")
		if username == "" {
			username = "user_" + userID[:8]
		}
		var emailEnc, emailToken string
		if info.Email != "" {
			emailEnc, _ = h.enc.Encrypt(info.Email)
			emailToken = h.hmac.Token(strings.ToLower(info.Email))
		}
		h.db.ExecContext(r.Context(),
			`INSERT INTO users(id,username,oauth_provider,oauth_id,email_enc,email_token) VALUES(?,?,?,?,?,?)`,
			userID, username, "google", info.Sub, nullStr(emailEnc), nullStr(emailToken),
		)
	} else if err != nil {
		http.Redirect(w, r, "amoon-eclipse:///auth?error=db", http.StatusFound)
		return
	}

	token, err := SignJWT(userID, username, h.jwtSecret)
	if err != nil {
		http.Redirect(w, r, "amoon-eclipse:///auth?error=jwt", http.StatusFound)
		return
	}

	params := url.Values{
		"token":    {token},
		"userId":   {userID},
		"username": {username},
	}
	http.Redirect(w, r, "amoon-eclipse:///auth?"+params.Encode(), http.StatusFound)
}

// ── Forgot username ────────────────────────────────────────────────────────

func (h *Handler) forgotUsername(w http.ResponseWriter, r *http.Request) {
	var req forgotReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}

	token := h.hmac.Token(strings.ToLower(req.Email))
	var username, emailEnc string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT username, email_enc FROM users WHERE email_token=?`, token,
	).Scan(&username, &emailEnc)
	if err != nil {
		jsonOK(w, map[string]string{"status": "sent"})
		return
	}
	if h.mailer == nil {
		jsonError(w, "email chưa được cấu hình", http.StatusServiceUnavailable)
		return
	}
	emailPlain, err := h.enc.Decrypt(emailEnc)
	if err != nil {
		jsonOK(w, map[string]string{"status": "sent"})
		return
	}
	html := fmt.Sprintf(`
<div style="font-family:sans-serif;max-width:400px;margin:40px auto;background:#0E0E1C;color:#F1F5F9;padding:32px;border-radius:16px;border:1px solid #1E1E30">
  <h2 style="color:#818CF8;margin:0 0 8px">🌙 AMoon Eclipse</h2>
  <p style="color:#64748B;margin:0 0 24px;font-size:13px">Khôi phục tên người dùng</p>
  <p style="margin:0 0 16px">Tên người dùng của bạn:</p>
  <div style="background:#1E1B4B;border-radius:12px;padding:20px;text-align:center;font-size:24px;font-weight:700;color:#818CF8">%s</div>
  <p style="color:#64748B;font-size:12px;margin:16px 0 0">Nếu bạn không yêu cầu, bỏ qua email này.</p>
</div>`, username)
	if err := h.mailer.Send(emailPlain, "Tên người dùng AMoon Eclipse của bạn", html); err != nil {
		log.Printf("ERROR forgotUsername to %s: %v", emailPlain, err)
		jsonError(w, "không gửi được email, thử lại sau", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "sent"})
}

// ── OTP helper ─────────────────────────────────────────────────────────────

func genOTP() string {
	const digits = "0123456789"
	otp := make([]byte, 6)
	for i := range otp {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))
		otp[i] = digits[n.Int64()]
	}
	return string(otp)
}
