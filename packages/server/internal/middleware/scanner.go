package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── Scanner Detection & IP Auto-Ban ─────────────────────────────────────────
//
// Tự động phát hiện IP đang quét lỗ hổng và block chúng.
// Trả về 404 (không phải 403) để scanner không biết rằng IP bị ban.

const (
	scanProbeThreshold = 8             // số lần hit scanner path tối đa
	scanWindow         = 60 * time.Second  // trong vòng 60 giây
	banDuration        = 2 * time.Hour     // ban 2 tiếng
)

// Các extension / path pattern của scanner
var scannerExtensions = map[string]bool{
	".php": true, ".asp": true, ".aspx": true, ".jsp": true,
	".rb":  true, ".py":  true, ".sh":   true, ".cgi": true,
	".sql": true, ".bak": true, ".swp":  true, ".log": true,
	".ini": true, ".cfg": true, ".conf": true, ".yml": true,
	".yaml": true, ".env": true, ".pem": true,
	".key": true, ".p12": true, ".pfx": true, ".cer": true,
	".ovpn": true, ".zip": true, ".tar": true, ".gz":  true,
}

var scannerPathPrefixes = []string{
	"wp-", "wordpress/", "phpmy", "phpmyadmin", "adminer",
	".git/", ".svn/", ".hg/", ".env", "xmlrpc",
	"actuator/", "admin/config", "manager/html",
	"solr/", "jmx-console", "web-console",
	"HNAP1", "evox/", "sdk",
}

var scannerPathContains = []string{
	"wp-config", "wp-login", "wp-admin",
	"phpinfo", "php-info", "php_info",
	"passwd", "shadow", "credentials",
	"/.well-known/acme", "autodiscover",
	"eval(", "base64_decode",
}

type probeRecord struct {
	count   int
	firstAt time.Time
}

type banRecord struct {
	bannedAt time.Time
}

var (
	probeMu sync.RWMutex
	probes  = make(map[string]*probeRecord)

	banMu   sync.RWMutex
	banned  = make(map[string]banRecord)
)

func init() {
	// Dọn dẹp định kỳ để tránh memory leak
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cleanupScannerMaps()
		}
	}()
}

func cleanupScannerMaps() {
	now := time.Now()

	probeMu.Lock()
	for ip, rec := range probes {
		if now.Sub(rec.firstAt) > scanWindow*2 {
			delete(probes, ip)
		}
	}
	probeMu.Unlock()

	banMu.Lock()
	for ip, rec := range banned {
		if now.Sub(rec.bannedAt) > banDuration {
			delete(banned, ip)
		}
	}
	banMu.Unlock()
}

// IsScannerPath exported để dùng trong route handler.
func IsScannerPath(path string) bool { return isScannerPath(path) }

// HackerRoast exported để dùng trong route handler.
func HackerRoast(w http.ResponseWriter, r *http.Request) { hackerRoast(w, r) }

// isScannerPath trả về true nếu path trông như scanner đang dò.
func isScannerPath(path string) bool {
	lower := strings.ToLower(path)

	// Check extension
	dot := strings.LastIndex(lower, ".")
	if dot >= 0 {
		ext := lower[dot:]
		if scannerExtensions[ext] {
			return true
		}
	}

	// Check path prefixes
	trimmed := strings.TrimPrefix(lower, "/")
	for _, p := range scannerPathPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}

	// Check path contains
	for _, s := range scannerPathContains {
		if strings.Contains(lower, s) {
			return true
		}
	}

	return false
}

func isBanned(ip string) bool {
	banMu.RLock()
	rec, ok := banned[ip]
	banMu.RUnlock()
	if !ok {
		return false
	}
	if time.Since(rec.bannedAt) > banDuration {
		banMu.Lock()
		delete(banned, ip)
		banMu.Unlock()
		return false
	}
	return true
}

func recordProbe(ip string) bool {
	now := time.Now()

	probeMu.Lock()
	rec, ok := probes[ip]
	if !ok {
		probes[ip] = &probeRecord{count: 1, firstAt: now}
		probeMu.Unlock()
		return false
	}

	// Reset nếu quá window
	if now.Sub(rec.firstAt) > scanWindow {
		rec.count = 1
		rec.firstAt = now
		probeMu.Unlock()
		return false
	}

	rec.count++
	shouldBan := rec.count >= scanProbeThreshold
	probeMu.Unlock()

	if shouldBan {
		banMu.Lock()
		banned[ip] = banRecord{bannedAt: now}
		banMu.Unlock()
		// Xóa probe record để tiết kiệm memory
		probeMu.Lock()
		delete(probes, ip)
		probeMu.Unlock()
		return true
	}
	return false
}

// hackerRoast trả về trang HTML "mồi" cho scanner — status 200 giả để
// scanner tưởng tìm thấy gì đó, nhưng nội dung là... lời chào thân ái :))
func hackerRoast(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Powered-By", "PHP/5.2.17") // bait fingerprint
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>404 Not Found</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0a0a0a;
    color: #00ff41;
    font-family: 'Courier New', monospace;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; text-align: center; padding: 2rem;
  }
  .terminal {
    border: 1px solid #00ff41;
    padding: 2rem 3rem;
    max-width: 600px;
    box-shadow: 0 0 30px #00ff4133;
  }
  pre { font-size: 0.7rem; color: #00ff41; line-height: 1.2; margin-bottom: 1.5rem; }
  h1 { font-size: 1.1rem; margin-bottom: 1rem; color: #ff0040; }
  p { font-size: 0.9rem; line-height: 1.7; color: #aaffaa; }
  .blink { animation: blink 1s step-end infinite; }
  @keyframes blink { 50% { opacity: 0; } }
  .red { color: #ff0040; }
  .dim { color: #445544; font-size: 0.75rem; margin-top: 1.5rem; }
</style>
</head>
<body>
<div class="terminal">
<pre>
 ██████╗  █████╗ ███╗   ██╗ ██████╗
 ██╔══██╗██╔══██╗████╗  ██║██╔════╝
 ██████╔╝███████║██╔██╗ ██║██║  ███╗
 ██╔══██╗██╔══██║██║╚██╗██║██║   ██║
 ██████╔╝██║  ██║██║ ╚████║╚██████╔╝
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝
</pre>
<h1>⚠ XIN CHÀO, HACKER BÉ NHỎ ⚠</h1>
<p>
  Ồ, mày đang tìm <span class="red">` + r.URL.Path + `</span> hả?<br><br>
  Không có gì ở đây đâu bạn ơi 🙂<br>
  Nhưng tao ghi nhận IP của mày rồi đó.<br><br>
  Tiếp tục đi, tao vẫn đang xem.<br>
  <span class="red">Mỗi request là một dòng log.</span>
</p>
<p class="dim">
  IP: ` + r.RemoteAddr + ` | ` + r.Header.Get("User-Agent") + `<br>
  <span class="blink">█</span> Đang ghi nhật ký...
</p>
</div>
</body>
</html>`))
}

// BlockScanners middleware chặn scanner và auto-ban IP dò lỗ hổng.
// Trả HTML "mồi" cho scanner thay vì 404 khô khan.
func BlockScanners(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := realClientIP(r)

		// IP đã bị ban → roast im lặng
		if isBanned(ip) {
			hackerRoast(w, r)
			return
		}

		// Kiểm tra path
		if isScannerPath(r.URL.Path) {
			recordProbe(ip)
			hackerRoast(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// realClientIP lấy IP thực từ header hoặc RemoteAddr.
func realClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}
