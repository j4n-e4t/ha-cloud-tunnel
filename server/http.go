package main

import (
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// botPatterns contains User-Agent substrings that identify bots and crawlers.
// These requests are blocked to prevent indexing of the tunnel endpoint.
var botPatterns = []string{
	"bot", "crawler", "spider", "crawling",
	"googlebot", "bingbot", "yandex", "baidu", "duckduckbot",
	"slurp", "ia_archiver", "archive.org",
	"facebookexternalhit", "twitterbot", "linkedinbot",
	"whatsapp", "telegrambot", "discordbot",
	"semrush", "ahrefs", "mj12bot", "dotbot", "petalbot",
	"bytespider", "gptbot", "chatgpt", "anthropic-ai",
	"claudebot", "cohere-ai", "ccbot",
	"curl", "wget", "python-requests", "httpie",
	"go-http-client", "java", "libwww", "lwp-trivial",
	"scrapy", "nutch", "httrack", "winhttp",
	"headlesschrome", "phantomjs", "selenium",
}

// activeHTTPConns tracks active HTTP connections for limiting
var activeHTTPConns int64

// StartHTTPServer starts the public HTTP server that proxies requests through the tunnel.
// When no tunnel is connected, it serves an info page with setup instructions.
// This function blocks forever.
func StartHTTPServer(s *Server) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleHTTPRequest(s, w, r)
	})

	// Chain middleware: security headers -> connection limit -> bot blocking -> handler
	srv := &http.Server{
		Addr:           PublicPort,
		Handler:        securityHeaders(connectionLimit(blockBots(handler))),
		MaxHeaderBytes: 1 << 20, // 1MB max header size
	}

	log.Printf("Public server started on %s (max %d concurrent)", PublicPort, MaxHTTPConns)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Public server failed: %v", err)
	}
}

// securityHeaders adds security headers to all responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// connectionLimit enforces maximum concurrent HTTP connections
func connectionLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt64(&activeHTTPConns, 1)
		defer atomic.AddInt64(&activeHTTPConns, -1)

		if current > MaxHTTPConns {
			http.Error(w, "Server too busy", http.StatusServiceUnavailable)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// blockBots is middleware that rejects requests from known bots and crawlers.
// It checks the User-Agent header against a list of known bot patterns.
func blockBots(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := strings.ToLower(r.UserAgent())

		// Block empty User-Agent (often automated tools)
		if ua == "" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Check for bot patterns in User-Agent
		for _, pattern := range botPatterns {
			if strings.Contains(ua, pattern) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// handleHTTPRequest routes incoming HTTP requests:
// - If tunnel is connected: proxy the request through the tunnel
// - If tunnel is disconnected: show info page with setup instructions or status
func handleHTTPRequest(s *Server, w http.ResponseWriter, r *http.Request) {
	session := s.GetSession()

	// No tunnel connected - show info page
	if session == nil {
		serveInfoPage(s, w)
		return
	}

	// Track stats
	s.State.RecordRequest()
	s.State.AddActiveConn()
	defer s.State.RemoveActiveConn()

	// Tunnel is connected - hijack connection and proxy through tunnel
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Open a stream through the multiplexed tunnel
	stream, err := session.Open()
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nFailed to connect to tunnel\n"))
		return
	}
	defer stream.Close()

	log.Printf("Proxying connection from %s", r.RemoteAddr)

	// Forward the original HTTP request to the tunnel
	if err := r.Write(stream); err != nil {
		log.Printf("Failed to write request: %v", err)
		return
	}

	// Forward any buffered data from the hijacked connection
	if buf.Reader.Buffered() > 0 {
		buffered := make([]byte, buf.Reader.Buffered())
		buf.Read(buffered)
		stream.Write(buffered)
	}

	// Bidirectional copy between client and tunnel with byte counting
	var wg sync.WaitGroup
	var bytesIn, bytesOut int64
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(stream, clientConn)
		bytesIn = n
		stream.Close()
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, stream)
		bytesOut = n
		clientConn.Close()
	}()

	wg.Wait()
	s.State.AddBytes(bytesIn, bytesOut)
	log.Printf("Connection closed for %s (in: %d, out: %d)", r.RemoteAddr, bytesIn, bytesOut)
}

// serveInfoPage renders the appropriate HTML page based on client state:
// - StateNull: Setup page with credentials for first-time configuration
// - StateDisconnected: Status page showing the client is offline
func serveInfoPage(s *Server, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if s.State.GetClientState() == StateNull {
		renderSetupPage(w, s)
	} else {
		renderStatusPage(w, s)
	}
}

// renderSetupPage renders the first-time setup page with credentials.
func renderSetupPage(w http.ResponseWriter, s *Server) {
	serverAddrRow := ""
	if s.ServerAddr != "" {
		serverAddrRow = fmt.Sprintf(`
<label>Server Address</label>
<div class="credential-row"><span class="credential" id="addr">%s</span><button onclick="copy('addr')">Copy</button></div>`,
			html.EscapeString(s.ServerAddr))
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel</title>
<meta http-equiv="refresh" content="5">
<style>
body{font-family:system-ui,sans-serif;max-width:700px;margin:40px auto;padding:20px;text-align:center}
.credential-row{display:flex;gap:10px;align-items:center;margin:10px 0}
.credential{flex:1;background:#f5f5f5;padding:15px;border-radius:8px;font-family:monospace;font-size:0.95rem;word-break:break-all;text-align:left}
label{font-weight:bold;display:block;margin-top:20px;text-align:left}
button{padding:10px 20px;border:none;border-radius:8px;background:#4CAF50;color:white;cursor:pointer;font-size:0.9rem}
button:hover{background:#45a049}
button:active{background:#3d8b40}
</style>
</head>
<body>
<h1>HA Cloud Tunnel</h1>
<p>Copy these credentials to your client configuration:</p>
%s
<label>Token</label>
<div class="credential-row"><span class="credential" id="token">%s</span><button onclick="copy('token')">Copy</button></div>

<label>Fingerprint</label>
<div class="credential-row"><span class="credential" id="fp">%s</span><button onclick="copy('fp')">Copy</button></div>

<hr>
<p>Status: waiting for client...</p>
<script>
function copy(id) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text);
}
</script>
</body>
</html>`,
		serverAddrRow,
		html.EscapeString(s.Token()),
		html.EscapeString(s.Fingerprint))
}

// renderStatusPage renders the status page with connection info and stats.
func renderStatusPage(w http.ResponseWriter, s *Server) {
	stats := s.State.GetStats()
	state := s.State.GetClientState()

	statusText := "Disconnected"
	statusClass := "disconnected"
	timeInfo := ""

	if state == StateConnected {
		statusText = "Connected"
		statusClass = "connected"
		if !stats.ConnectedAt.IsZero() {
			timeInfo = fmt.Sprintf("Connected for %s", formatDuration(time.Since(stats.ConnectedAt)))
		}
	} else {
		if !stats.LastDisconnectAt.IsZero() {
			timeInfo = fmt.Sprintf("Disconnected %s ago", formatDuration(time.Since(stats.LastDisconnectAt)))
		}
	}

	lastRequest := "Never"
	if !stats.LastRequestAt.IsZero() {
		lastRequest = fmt.Sprintf("%s ago", formatDuration(time.Since(stats.LastRequestAt)))
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel</title>
<meta http-equiv="refresh" content="5">
<style>
body{font-family:system-ui,sans-serif;max-width:600px;margin:40px auto;padding:20px;background:#f5f5f5}
.card{background:white;border-radius:12px;padding:24px;margin-bottom:16px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
h1{margin:0 0 8px 0;font-size:1.5rem}
.status{display:inline-block;padding:4px 12px;border-radius:20px;font-weight:500;font-size:0.9rem}
.connected{background:#d4edda;color:#155724}
.disconnected{background:#f8d7da;color:#721c24}
.time-info{color:#666;font-size:0.9rem;margin-top:8px}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.stat{text-align:center}
.stat-value{font-size:1.5rem;font-weight:bold;color:#333}
.stat-label{font-size:0.8rem;color:#666;text-transform:uppercase}
</style>
</head>
<body>
<div class="card">
<h1>HA Cloud Tunnel</h1>
<span class="status %s">%s</span>
<div class="time-info">%s</div>
</div>
<div class="card">
<div class="stats">
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Total Requests</div></div>
<div class="stat"><div class="stat-value">%d</div><div class="stat-label">Active Connections</div></div>
<div class="stat"><div class="stat-value">%s</div><div class="stat-label">Data In</div></div>
<div class="stat"><div class="stat-value">%s</div><div class="stat-label">Data Out</div></div>
</div>
</div>
<div class="card">
<div class="stats">
<div class="stat"><div class="stat-value" style="font-size:1rem">%s</div><div class="stat-label">Last Request</div></div>
</div>
</div>
</body>
</html>`,
		statusClass, statusText, timeInfo,
		stats.TotalRequests, stats.ActiveConns,
		formatBytes(stats.BytesIn), formatBytes(stats.BytesOut),
		lastRequest)
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

// formatBytes formats bytes in a human-readable way.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
