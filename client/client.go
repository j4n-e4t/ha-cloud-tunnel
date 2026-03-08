package main

import (
	"log"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Client manages the tunnel connection to the remote server.
// It handles reconnection logic and distributes incoming streams to handlers.
type Client struct {
	serverAddr  string         // Remote server address (host:port)
	token       string         // Authentication token
	clientKey   string         // Client key for server binding
	fingerprint string         // Expected server certificate fingerprint
	targetAddr  string         // Local target address to proxy to
	session     *yamux.Session // Active multiplexed session (nil if disconnected)
	sessionMu   sync.RWMutex   // Protects session field
	streamCount int64          // Counter for logging stream IDs
	streamMu    sync.Mutex     // Protects streamCount
}

// NewClient creates a new tunnel client with the given configuration.
func NewClient(serverAddr, token, clientKey, fingerprint, targetAddr string) *Client {
	return &Client{
		serverAddr:  serverAddr,
		token:       token,
		clientKey:   clientKey,
		fingerprint: fingerprint,
		targetAddr:  targetAddr,
	}
}

// Run starts the main connection loop. It connects to the server,
// handles streams until disconnection, then reconnects. Never returns.
func (c *Client) Run() {
	for {
		log.Printf("Connecting to server at %s...", c.serverAddr)

		err := c.connect()
		if err != nil {
			log.Printf("Connection failed: %v", err)
			log.Printf("Reconnecting in %v...", ReconnectDelay)
			time.Sleep(ReconnectDelay)
			continue
		}

		log.Println("Connected to server, handling streams...")

		c.handleStreams()

		log.Printf("Disconnected, reconnecting in %v...", ReconnectDelay)
		time.Sleep(ReconnectDelay)
	}
}

// GetSession returns the current session, or nil if not connected.
func (c *Client) GetSession() *yamux.Session {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.session
}

// SetSession stores a new session, closing any existing one.
func (c *Client) SetSession(session *yamux.Session) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.session != nil {
		c.session.Close()
	}
	c.session = session
}

// NextStreamID returns an incrementing stream ID for logging.
func (c *Client) NextStreamID() int64 {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	c.streamCount++
	return c.streamCount
}

// handleStreams accepts incoming streams from the server and spawns
// goroutines to proxy them to the target.
func (c *Client) handleStreams() {
	session := c.GetSession()
	if session == nil {
		return
	}

	for {
		stream, err := session.Accept()
		if err != nil {
			log.Printf("Stream accept error: %v", err)
			return
		}

		streamID := c.NextStreamID()
		go proxyStream(stream, streamID, c.targetAddr)
	}
}
