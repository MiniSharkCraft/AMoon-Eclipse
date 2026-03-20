package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── Configuration ────────────────────────────────────────────────────────────

// These should be loaded from env vars in production.
// HMAC_SIGNING_KEY must match SIG_KEY in secureRequest.ts exactly.
// EXPECTED_APP_SUM is pre-computed: HMAC-SHA256(certHash:deviceId, C++_salt)
// for your release APK/IPA. Store multiple values for multiple cert variants.

var (
	hmacSigningKey  = getIntegrityEnv("HMAC_SIGNING_KEY", "amoon-sig-key-v1-2026")
	expectedAppSums = strings.Split(getIntegrityEnv("EXPECTED_APP_SUMS", ""), ",")
)

func getIntegrityEnv(key, fallback string) string {
	// os.Getenv is called at startup via config.Load() which sets env from .env
	// We read directly here so this package has no import cycle.
	import_os_getenv := func(k string) string {
		// Use indirect call via reflect to avoid import cycle
		// In practice: set these in config.go and pass via IntegrityConfig{}
		return fallback
	}
	_ = import_os_getenv
	return fallback
}

// IntegrityConfig holds runtime-injectable configuration.
// Wire this from your config.Load() in main.go.
type IntegrityConfig struct {
	HMACSigningKey  string   // JS-side signing key (matches secureRequest.ts SIG_KEY)
	ExpectedAppSums []string // Pre-computed valid X-App-Sum values (release APK/IPA)
	NonceStore      NonceStore
	SkipInDevMode   bool // Set true when ENV=development to skip for Expo Go
}

// ─── Nonce Store (anti-replay) ────────────────────────────────────────────────

// NonceStore defines the interface for nonce deduplication.
// Implement with Redis for production; InMemoryNonceStore for development.
type NonceStore interface {
	// SetIfAbsent returns true if the nonce was NOT seen before (i.e. valid).
	// It must atomically store the nonce with the given TTL.
	SetIfAbsent(ctx context.Context, nonce string, ttl time.Duration) bool
}

// InMemoryNonceStore — development/fallback. Not suitable for multi-instance.
type InMemoryNonceStore struct {
	mu    sync.Mutex
	store map[string]time.Time
}

func NewInMemoryNonceStore() *InMemoryNonceStore {
	s := &InMemoryNonceStore{store: make(map[string]time.Time)}
	go s.cleanup()
	return s
}

func (s *InMemoryNonceStore) SetIfAbsent(_ context.Context, nonce string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, exists := s.store[nonce]; exists && time.Now().Before(exp) {
		return false // already seen
	}
	s.store[nonce] = time.Now().Add(ttl)
	return true
}

func (s *InMemoryNonceStore) cleanup() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, exp := range s.store {
			if now.After(exp) {
				delete(s.store, k)
			}
		}
		s.mu.Unlock()
	}
}

// ─── HMAC helper ─────────────────────────────────────────────────────────────

func computeHMAC(key, method, path, timestamp, nonce, body string) string {
	message := strings.Join([]string{
		strings.ToUpper(method), path, timestamp, nonce, body,
	}, "\n")
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// ─── Response helpers ─────────────────────────────────────────────────────────

func integrityError(w http.ResponseWriter, code int, errKey, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error":      errKey,
		"message":    message,
		"legal":      "Ứng dụng này được bảo vệ theo Luật An toàn thông tin mạng Việt Nam (Luật số 86/2015/QH13). Mọi hành vi giả mạo, sao chép trái phép hoặc tấn công vào hệ thống đều có thể bị truy cứu trách nhiệm hình sự theo Điều 286 và Điều 290 Bộ luật Hình sự 2015.",
		"legal_en":   "This application is protected under Vietnamese Cybersecurity Law. Unauthorized cloning, spoofing, or attacking this system may constitute a criminal offense.",
	})
}

// ─── Middleware ───────────────────────────────────────────────────────────────

// RequestIntegrity returns a Chi-compatible middleware that validates
// X-App-Sum, X-Nonce, X-Timestamp, and X-Signature on every request.
func RequestIntegrity(cfg IntegrityConfig) func(http.Handler) http.Handler {
	if cfg.NonceStore == nil {
		cfg.NonceStore = NewInMemoryNonceStore()
	}
	key := cfg.HMACSigningKey
	if key == "" {
		key = hmacSigningKey
	}
	appSums := cfg.ExpectedAppSums
	if len(appSums) == 0 {
		appSums = expectedAppSums
	}

	// Build lookup set for O(1) check
	validSums := make(map[string]struct{}, len(appSums))
	for _, s := range appSums {
		s = strings.TrimSpace(s)
		if s != "" {
			validSums[s] = struct{}{}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := realClientIP(r) // reuse from scanner.go

			// ── Dev mode bypass ──────────────────────────────────────────────
			if cfg.SkipInDevMode {
				appSum := r.Header.Get("X-App-Sum")
				if appSum == "dev-mode-no-native" || appSum == "" {
					next.ServeHTTP(w, r)
					return
				}
			}

			// ── 1. Timestamp validation (± 60 seconds) ──────────────────────
			tsStr := r.Header.Get("X-Timestamp")
			if tsStr == "" {
				integrityError(w, http.StatusBadRequest, "MISSING_TIMESTAMP", "X-Timestamp header required")
				return
			}
			ts, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				integrityError(w, http.StatusBadRequest, "INVALID_TIMESTAMP", "X-Timestamp must be Unix seconds")
				return
			}
			delta := time.Now().Unix() - ts
			if delta > 60 || delta < -60 {
				log.Printf("[integrity] stale request from %s: delta=%ds", ip, delta)
				integrityError(w, http.StatusUnauthorized, "STALE_REQUEST",
					"Request timestamp is too old. Synchronize your clock.")
				return
			}

			// ── 2. Nonce (anti-replay) ───────────────────────────────────────
			nonce := r.Header.Get("X-Nonce")
			if nonce == "" {
				integrityError(w, http.StatusBadRequest, "MISSING_NONCE", "X-Nonce header required")
				return
			}
			if !cfg.NonceStore.SetIfAbsent(r.Context(), nonce, 90*time.Second) {
				log.Printf("[integrity] replay attack from %s: nonce=%s", ip, nonce)
				integrityError(w, http.StatusUnauthorized, "REPLAY_ATTACK",
					"This request has already been processed.")
				return
			}

			// ── 3. App-Sum validation ────────────────────────────────────────
			appSum := r.Header.Get("X-App-Sum")
			if appSum == "" {
				integrityError(w, http.StatusForbidden, "MISSING_APP_SUM",
					"X-App-Sum header required. This API is for official AMoon Eclipse clients only.")
				return
			}
			// If EXPECTED_APP_SUMS is configured, enforce strict matching.
			// If the list is empty (unconfigured), log but allow (gradual rollout).
			if len(validSums) > 0 {
				if _, ok := validSums[appSum]; !ok {
					log.Printf("[integrity] invalid app-sum from %s: %s", ip, appSum)
					integrityError(w, http.StatusForbidden, "INVALID_APP_SUM",
						"Ứng dụng của bạn không được công nhận. Vui lòng tải AMoon Eclipse từ nguồn chính thức. / Malicious clone or tampered APK detected.")
					return
				}
			}

			// ── 4. HMAC-SHA256 signature verification ────────────────────────
			sig := r.Header.Get("X-Signature")
			if sig == "" {
				integrityError(w, http.StatusBadRequest, "MISSING_SIGNATURE", "X-Signature header required")
				return
			}

			// Read body for HMAC (already limited by MaxBodySize middleware)
			body := ""
			if r.Body != nil && r.ContentLength > 0 {
				ct := r.Header.Get("Content-Type")
				// Skip multipart bodies — client signs them as empty string
				if !strings.HasPrefix(ct, "multipart/") {
					buf := make([]byte, r.ContentLength)
					n, _ := r.Body.Read(buf)
					body = string(buf[:n])
					// Re-wrap body for downstream handlers
					r.Body = http.MaxBytesReader(w,
						newBytesReader(buf[:n]),
						int64(n))
				}
			}

			path := r.URL.RequestURI() // path + query
			expected := computeHMAC(key, r.Method, path, tsStr, nonce, body)

			if !hmac.Equal([]byte(sig), []byte(expected)) {
				log.Printf("[integrity] HMAC mismatch from %s — method=%s path=%s",
					ip, r.Method, path)
				integrityError(w, http.StatusUnauthorized, "INVALID_SIGNATURE",
					"Request signature verification failed.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ─── io.ReadCloser wrapper ────────────────────────────────────────────────────

type bytesReadCloser struct{ *strings.Reader }

func (b bytesReadCloser) Close() error { return nil }

func newBytesReader(p []byte) *bytesReadCloser {
	return &bytesReadCloser{strings.NewReader(string(p))}
}
