package main

import (
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
)

// activeHTTPConns tracks active HTTP connections for limiting
var activeHTTPConns int64

// StartHTTPServer starts the public HTTP server that proxies requests through the tunnel.
// When no tunnel is connected, it serves an info page with setup instructions.
// This function blocks forever.
func StartHTTPServer(s *Server) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleHTTPRequest(s, w, r)
	})

	srv := &http.Server{
		Addr:           PublicPort,
		Handler:        securityHeaders(connectionLimit(handler)),
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

	// Bidirectional copy between client and tunnel
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, clientConn)
		stream.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, stream)
		clientConn.Close()
	}()

	wg.Wait()
	log.Printf("Connection closed for %s", r.RemoteAddr)
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

// renderStatusPage renders a simple status page.
func renderStatusPage(w http.ResponseWriter, s *Server) {
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:system-ui,sans-serif;max-width:600px;margin:40px auto;padding:20px;text-align:center}</style>
</head>
<body>
<h1>HA Cloud Tunnel</h1>
<p>Status: disconnected</p>
<p>Waiting for client to reconnect...</p>
</body>
</html>`)
}
