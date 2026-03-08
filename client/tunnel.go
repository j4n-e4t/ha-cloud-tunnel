package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

// connect establishes a TLS connection to the server, verifies the certificate
// fingerprint, authenticates with the token, and creates a yamux session.
func (c *Client) connect() error {
	// Build TLS config with fingerprint verification
	tlsConfig := c.buildTLSConfig()

	// Establish TLS connection
	conn, err := c.dial(tlsConfig)
	if err != nil {
		return err
	}

	// Authenticate with server
	if err := c.authenticate(conn); err != nil {
		conn.Close()
		return err
	}

	// Create multiplexed session
	session, err := c.createSession(conn)
	if err != nil {
		conn.Close()
		return err
	}

	c.SetSession(session)
	return nil
}

// buildTLSConfig creates a TLS configuration that verifies the server certificate
// against the expected fingerprint. This provides security equivalent to certificate
// pinning without requiring a CA.
func (c *Client) buildTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // We verify manually via fingerprint
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no server certificate")
			}

			cert := cs.PeerCertificates[0]
			hash := sha256.Sum256(cert.Raw)
			actual := "SHA256:" + strings.ToUpper(hex.EncodeToString(hash[:]))

			if actual != c.fingerprint {
				return fmt.Errorf("fingerprint mismatch: expected %s, got %s", c.fingerprint, actual)
			}

			log.Println("Server fingerprint verified")
			return nil
		},
	}
}

// dial establishes a TLS connection to the server with timeout.
func (c *Client) dial(tlsConfig *tls.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: ConnectTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", c.serverAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS dial failed: %w", err)
	}
	return conn, nil
}

// authenticate sends the token and client key to the server and waits for acknowledgment.
// Returns an error if authentication fails.
func (c *Client) authenticate(conn net.Conn) error {
	// Send authentication token
	if _, err := conn.Write([]byte(c.token)); err != nil {
		return fmt.Errorf("failed to send token: %w", err)
	}

	// Send client key
	if _, err := conn.Write([]byte(c.clientKey)); err != nil {
		return fmt.Errorf("failed to send client key: %w", err)
	}

	// Wait for server acknowledgment
	conn.SetReadDeadline(time.Now().Add(AckTimeout))
	ack := make([]byte, 32)
	n, err := conn.Read(ack)
	if err != nil {
		return fmt.Errorf("failed to read ack: %w", err)
	}
	conn.SetReadDeadline(time.Time{}) // Clear deadline

	response := string(ack[:n])
	if response != "OK" {
		return fmt.Errorf("authentication failed: %s", response)
	}

	log.Println("Authentication successful")
	return nil
}

// createSession creates a yamux session over the connection.
// The client acts as the yamux server (accepts streams from the tunnel server).
func (c *Client) createSession(conn net.Conn) (*yamux.Session, error) {
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second

	session, err := yamux.Server(conn, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create yamux session: %w", err)
	}

	return session, nil
}
