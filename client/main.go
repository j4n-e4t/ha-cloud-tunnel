package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	infoPort       = ":8099"
	reconnectDelay = 5 * time.Second
	connectTimeout = 30 * time.Second
)

type Client struct {
	serverAddr    string
	token         string
	target        string
	session       *yamux.Session
	sessionMu     sync.RWMutex
	status        string
	statusMu      sync.RWMutex
	lastError     string
	lastErrorMu   sync.RWMutex
	connections   int64
	connectionsMu sync.Mutex
}

func main() {
	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = "localhost:7000"
	}

	token := os.Getenv("TOKEN")
	if token == "" {
		log.Fatal("TOKEN environment variable is required")
	}

	if len(token) != 32 {
		log.Fatal("TOKEN must be exactly 32 characters")
	}

	target := os.Getenv("TARGET")
	if target == "" {
		target = "homeassistant:8123"
	}

	c := &Client{
		serverAddr: serverAddr,
		token:      token,
		target:     target,
		status:     "disconnected",
	}

	// Start info HTTP server
	go c.startInfoServer()

	// Main connection loop
	c.connectLoop()
}

func (c *Client) setStatus(status string) {
	c.statusMu.Lock()
	c.status = status
	c.statusMu.Unlock()
}

func (c *Client) getStatus() string {
	c.statusMu.RLock()
	defer c.statusMu.RUnlock()
	return c.status
}

func (c *Client) setLastError(err string) {
	c.lastErrorMu.Lock()
	c.lastError = err
	c.lastErrorMu.Unlock()
}

func (c *Client) getLastError() string {
	c.lastErrorMu.RLock()
	defer c.lastErrorMu.RUnlock()
	return c.lastError
}

func (c *Client) connectLoop() {
	for {
		c.setStatus("connecting")
		log.Printf("Connecting to server at %s...", c.serverAddr)

		err := c.connect()
		if err != nil {
			c.setStatus("disconnected")
			c.setLastError(err.Error())
			log.Printf("Connection failed: %v", err)
			log.Printf("Reconnecting in %v...", reconnectDelay)
			time.Sleep(reconnectDelay)
			continue
		}

		c.setStatus("connected")
		c.setLastError("")
		log.Println("Connected to server, handling streams...")

		// Handle incoming streams
		c.handleStreams()

		c.setStatus("disconnected")
		log.Printf("Disconnected, reconnecting in %v...", reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

func (c *Client) connect() error {
	// Connect to server
	conn, err := net.DialTimeout("tcp", c.serverAddr, connectTimeout)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	// Send token
	_, err = conn.Write([]byte(c.token))
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to send token: %w", err)
	}

	// Wait for acknowledgment
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ack := make([]byte, 32)
	n, err := conn.Read(ack)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to read ack: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	ackStr := string(ack[:n])
	if ackStr != "OK" {
		conn.Close()
		return fmt.Errorf("authentication failed: %s", ackStr)
	}

	log.Println("Authentication successful")

	// Create yamux session (server mode - we accept streams from server)
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second

	session, err := yamux.Server(conn, config)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create yamux session: %w", err)
	}

	c.sessionMu.Lock()
	if c.session != nil {
		c.session.Close()
	}
	c.session = session
	c.sessionMu.Unlock()

	return nil
}

func (c *Client) handleStreams() {
	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()

	if session == nil {
		return
	}

	for {
		stream, err := session.Accept()
		if err != nil {
			log.Printf("Stream accept error: %v", err)
			return
		}

		c.connectionsMu.Lock()
		c.connections++
		connNum := c.connections
		c.connectionsMu.Unlock()

		go c.handleStream(stream, connNum)
	}
}

func (c *Client) handleStream(stream net.Conn, connNum int64) {
	defer stream.Close()

	log.Printf("[%d] New stream, connecting to %s...", connNum, c.target)

	// Connect to target
	haConn, err := net.DialTimeout("tcp", c.target, 10*time.Second)
	if err != nil {
		log.Printf("[%d] Failed to connect to HA: %v", connNum, err)
		return
	}
	defer haConn.Close()

	log.Printf("[%d] Connected to Home Assistant, proxying...", connNum)

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(haConn, stream)
		haConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(stream, haConn)
		stream.Close()
	}()

	wg.Wait()
	log.Printf("[%d] Stream closed", connNum)
}

func (c *Client) startInfoServer() {
	http.HandleFunc("/", c.handleInfo)
	http.HandleFunc("/health", c.handleHealth)

	log.Printf("Info server started on %s", infoPort)
	if err := http.ListenAndServe(infoPort, nil); err != nil {
		log.Printf("Info server failed: %v", err)
	}
}

func (c *Client) handleInfo(w http.ResponseWriter, r *http.Request) {
	status := c.getStatus()
	lastError := c.getLastError()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Error page - shown when there's an auth or connection error
	if lastError != "" {
		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel - Error</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:monospace;max-width:600px;margin:40px auto;padding:20px}pre{background:#fff0f0;padding:10px;overflow-x:auto}</style>
</head>
<body>
<h1>HA Cloud Tunnel</h1>
<p>Status: %s</p>
<p>Error:</p>
<pre>%s</pre>
<hr>
<p>Server: %s<br>Target: %s</p>
</body>
</html>`, status, lastError, c.serverAddr, c.target)
		w.Write([]byte(html))
		return
	}

	// Status page - normal operation
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>HA Cloud Tunnel</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:monospace;max-width:600px;margin:40px auto;padding:20px}</style>
</head>
<body>
<h1>HA Cloud Tunnel</h1>
<p>Status: %s</p>
<hr>
<p>Server: %s<br>Target: %s</p>
</body>
</html>`, status, c.serverAddr, c.target)
	w.Write([]byte(html))
}

func (c *Client) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := c.getStatus()

	if status == "connected" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(status))
	}
}
