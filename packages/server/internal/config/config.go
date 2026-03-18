package config

import (
	"os"
	"strings"
)

type Config struct {
	Port             string
	DBDSN            string // MySQL/MariaDB DSN
	JWTSecret        string
	DBEncryptionKey  string // 64-char hex = 32 bytes, AES-256-GCM cho PII
	DBHmacKey        string // 64-char hex = 32 bytes, HMAC-SHA256 email token
	AllowedOrigins   []string
	Env              string
	BaseURL            string // Public URL, dùng cho OAuth redirect (VD: https://yourdomain.com)
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
	origins := strings.Split(getEnv("ALLOWED_ORIGINS", "*"), ",")
	return &Config{
		Port:            getEnv("PORT", "8080"),
		DBDSN:           mustEnv("DB_DSN"),
		JWTSecret:       mustEnv("JWT_SECRET"),
		DBEncryptionKey: mustEnv("DB_ENCRYPTION_KEY"),
		DBHmacKey:       mustEnv("DB_HMAC_KEY"),
		AllowedOrigins:  origins,
		Env:             getEnv("ENV", "production"),
		BaseURL:            getEnv("BASE_URL", "http://localhost:8080"),
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
