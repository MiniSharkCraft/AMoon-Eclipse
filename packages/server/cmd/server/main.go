package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"amoon-eclipse/server/internal/auth"
	"amoon-eclipse/server/internal/blocks"
	"amoon-eclipse/server/internal/calls"
	"amoon-eclipse/server/internal/config"
	dbpkg "amoon-eclipse/server/internal/db"
	dbcrypto "amoon-eclipse/server/internal/crypto"
	"amoon-eclipse/server/internal/email"
	"amoon-eclipse/server/internal/friends"
	"amoon-eclipse/server/internal/messages"
	"amoon-eclipse/server/internal/moderation"
	mw "amoon-eclipse/server/internal/middleware"
	"amoon-eclipse/server/internal/notes"
	"amoon-eclipse/server/internal/pending"
	"amoon-eclipse/server/internal/rooms"
	"amoon-eclipse/server/internal/users"
	"amoon-eclipse/server/internal/ws"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//go:embed web
var webFS embed.FS

func main() {
	cfg := config.Load()

	db, err := dbpkg.Open(cfg.DBDSN)
	if err != nil {
		log.Fatalf("mở DB thất bại: %v", err)
	}
	defer db.Close()

	enc, err := dbcrypto.NewFieldEncryptor(cfg.DBEncryptionKey)
	if err != nil {
		log.Fatalf("field encryptor: %v", err)
	}
	hmacT, err := dbcrypto.NewHmacTokener(cfg.DBHmacKey)
	if err != nil {
		log.Fatalf("hmac tokener: %v", err)
	}

	// WebSocket hub
	hub := ws.NewHub()
	go hub.Run()

	// Handlers
	var mailer *email.Sender
	if cfg.SMTPHost != "" && cfg.SMTPUser != "" {
		mailer = email.NewSender(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.EmailFrom)
	}
	authHandler       := auth.NewHandler(db, cfg.JWTSecret, enc, hmacT, cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.FacebookAppID, mailer)
	roomsHandler      := rooms.NewHandler(db)
	msgsHandler       := messages.NewHandler(db, hub)
	notesHandler      := notes.NewHandler(db)
	friendsHandler    := friends.NewHandler(db)
	usersHandler      := users.NewHandler(db)
	callsHandler      := calls.NewHandler(cfg.CFTurnTokenID, cfg.CFTurnAPIToken)
	moderationHandler := moderation.NewHandler(db)
	pendingHandler    := pending.NewHandler(db)
	blocksHandler     := blocks.NewHandler(db)

	// Router
	r := chi.NewRouter()
	r.Use(mw.BlockScanners)           // FIRST: auto-ban IP quét lỗ hổng (trước cả logger)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware(cfg.AllowedOrigins))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(mw.SecurityHeaders)
	r.Use(mw.MaxBodySize(512 * 1024))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Serve web frontend — chỉ serve SPA cho path hợp lệ, block scanner paths
	webDist, _ := fs.Sub(webFS, "web")
	webServer := http.FileServer(http.FS(webDist))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Chặn scanner paths ngay tại đây (defense-in-depth)
		if mw.IsScannerPath(path) {
			mw.HackerRoast(w, r)
			return
		}

		if _, err := webDist.Open(path[1:]); err != nil {
			// Không có extension → SPA route, serve index.html
			if !strings.Contains(path, ".") {
				r.URL.Path = "/"
				webServer.ServeHTTP(w, r)
				return
			}
			// Có extension nhưng file không tồn tại → 404
			http.NotFound(w, r)
			return
		}
		webServer.ServeHTTP(w, r)
	})

	// Public routes — rate limited (brute-force protection)
	r.Route("/api/auth", func(r chi.Router) {
		r.Use(mw.RateLimitAuth)
		r.Mount("/", authHandler.Routes())
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(mw.Auth(cfg.JWTSecret))
		r.Use(mw.RateLimitAPI)

		r.Route("/api/rooms", func(r chi.Router) {
			r.Mount("/", roomsHandler.Routes())
		})
		r.Route("/api/messages", func(r chi.Router) {
			r.Mount("/", msgsHandler.Routes())
		})
		r.Route("/api/notes", func(r chi.Router) {
			r.Mount("/", notesHandler.Routes())
		})
		r.Route("/api/friends", func(r chi.Router) {
			r.Mount("/", friendsHandler.Routes())
		})
		r.Route("/api/users", func(r chi.Router) {
			r.Mount("/", usersHandler.Routes())
		})
		r.Route("/api/moderation", func(r chi.Router) {
			r.Mount("/", moderationHandler.Routes())
		})
		r.Route("/api/pending", func(r chi.Router) {
			r.Mount("/", pendingHandler.Routes())
		})
		r.Route("/api/blocks", func(r chi.Router) {
			r.Mount("/", blocksHandler.Routes())
		})
		r.Get("/api/calls/turn-credentials", callsHandler.GetTURNCredentials)

		// WebSocket (token via query param) — separate rate limit
		r.With(mw.RateLimitWS).Get("/ws", hub.ServeWS)
	})

	// Cleanup expired notes mỗi 30 phút
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			notes.CleanupExpired(db)
		}
	}()

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		log.Printf("🌙 AMoon Eclipse server running on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowAll := len(allowedOrigins) == 1 && allowedOrigins[0] == "*"
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if allowAll || allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
