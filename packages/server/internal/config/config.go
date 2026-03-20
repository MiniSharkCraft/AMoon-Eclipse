package config

import (
	"bufio"
	"os"
	"strings"
)

// loadDotEnv đọc file .env trong working directory và set các biến chưa có.
// Format: KEY=VALUE (bỏ qua dòng trống và comment #)
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // không có file .env thì bỏ qua
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// Strip inline comment
		if ci := strings.Index(val, " #"); ci >= 0 {
			val = strings.TrimSpace(val[:ci])
		}
		// Strip surrounding quotes
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		// Chỉ set nếu chưa có (env var thật được ưu tiên hơn .env)
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
}

type Config struct {
	Port             string
	DBDSN            string // MySQL/MariaDB DSN
	JWTSecret        string
	DBEncryptionKey  string // 64-char hex = 32 bytes, AES-256-GCM cho PII
	DBHmacKey        string // 64-char hex = 32 bytes, HMAC-SHA256 email token
	AllowedOrigins   []string
	Env              string
	GoogleClientID     string // Web client ID
	GoogleClientSecret string // Web client secret
	CFTurnTokenID      string // Cloudflare TURN token ID
	CFTurnAPIToken     string // Cloudflare TURN API token
	FacebookAppID    string // App ID để verify token
	SMTPHost         string // VD: mail.yourdomain.com
	SMTPPort         string // 587 hoặc 465
	SMTPUser         string // địa chỉ email đầy đủ
	SMTPPass         string // mật khẩu email
	EmailFrom        string // VD: AMoon Eclipse <noreply@yourdomain.com>
}

func Load() *Config {
	loadDotEnv(".env")
	origins := strings.Split(getEnv("ALLOWED_ORIGINS", "*"), ",")
	return &Config{
		Port:            getEnv("PORT", getEnv("P_SERVER_PORT", "8080")),
		DBDSN:           mustEnv("DB_DSN"),
		JWTSecret:       mustEnv("JWT_SECRET"),
		DBEncryptionKey: mustEnv("DB_ENCRYPTION_KEY"),
		DBHmacKey:       mustEnv("DB_HMAC_KEY"),
		AllowedOrigins:  origins,
		Env:             getEnv("ENV", "production"),
		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		CFTurnTokenID:      getEnv("CF_TURN_TOKEN_ID", ""),
		CFTurnAPIToken:     getEnv("CF_TURN_API_TOKEN", ""),
		FacebookAppID:   getEnv("FACEBOOK_APP_ID", ""),
		SMTPHost:        getEnv("SMTP_HOST", ""),
		SMTPPort:        getEnv("SMTP_PORT", "587"),
		SMTPUser:        getEnv("SMTP_USER", ""),
		SMTPPass:        getEnv("SMTP_PASS", ""),
		EmailFrom:       getEnv("EMAIL_FROM", "AMoon Eclipse <noreply@amoon-eclipse.app>"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("biến môi trường bắt buộc chưa set: " + key)
	}
	return v
}
