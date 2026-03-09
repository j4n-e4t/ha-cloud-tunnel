package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// ClientState represents the connection status of the tunnel client.
type ClientState string

const (
	StateNull         ClientState = "NULL"         // No client has ever connected
	StateConnected    ClientState = "CONNECTED"    // Client is currently connected
	StateDisconnected ClientState = "DISCONNECTED" // Client was connected but disconnected
)

// persistedState is the data saved to disk.
type persistedState struct {
	Token     string `json:"token"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	ClientKey string `json:"client_key,omitempty"` // Bound client key (set on first connection)
}

// Stats holds runtime statistics for the tunnel (memory-only, not persisted).
type Stats struct {
	TotalRequests    int64     // Total HTTP requests proxied
	ActiveConns      int64     // Currently active connections
	BytesIn          int64     // Total bytes received from clients
	BytesOut         int64     // Total bytes sent to clients
	ConnectedAt      time.Time // When client connected (zero if disconnected)
	LastRequestAt    time.Time // Time of last request
	LastDisconnectAt time.Time // When client last disconnected
}

// State holds server credentials and runtime connection state.
// Token, certificate, and client key are persisted to disk.
type State struct {
	token     string // Authentication token (sk-xxxx format)
	certPEM   string // PEM-encoded server certificate
	keyPEM    string // PEM-encoded private key
	clientKey string // Bound client key (empty until first connection)
	connected bool   // True if client is currently connected (memory-only)
	stats     Stats  // Runtime statistics (memory-only)
	mu        sync.RWMutex
}

var stateInstance *State
var stateOnce sync.Once

// GetState returns the singleton State instance.
// On first call, loads credentials from disk or creates new ones.
func GetState() *State {
	stateOnce.Do(func() {
		stateInstance = &State{}
		if err := stateInstance.load(); err != nil {
			log.Printf("Creating new credentials: %v", err)
			stateInstance.token = generateToken()
			stateInstance.generateCert()
			stateInstance.save()
		}
	})
	return stateInstance
}

// load reads credentials from the state file.
// Returns an error if the file doesn't exist or contains invalid data.
func (s *State) load() error {
	data, err := os.ReadFile(StateFile)
	if err != nil {
		return err
	}

	var p persistedState
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}

	// Validate token format: "sk-" prefix + 32 hex chars = 35 total
	if len(p.Token) != 35 || p.Token[:3] != "sk-" {
		return fmt.Errorf("invalid token format")
	}
	if p.CertPEM == "" || p.KeyPEM == "" {
		return fmt.Errorf("missing certificate")
	}

	s.mu.Lock()
	s.token = p.Token
	s.certPEM = p.CertPEM
	s.keyPEM = p.KeyPEM
	s.clientKey = p.ClientKey
	s.mu.Unlock()

	log.Println("Loaded credentials from disk")
	return nil
}

// save writes credentials to the state file with restricted permissions.
func (s *State) save() error {
	s.mu.RLock()
	p := persistedState{
		Token:     s.token,
		CertPEM:   s.certPEM,
		KeyPEM:    s.keyPEM,
		ClientKey: s.clientKey,
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(StateFile, data, 0600); err != nil {
		log.Printf("Warning: could not save credentials: %v", err)
		return err
	}
	return nil
}

// GetToken returns the authentication token.
func (s *State) GetToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

// VerifyOrBindClientKey checks the client key against the stored one.
// On first connection (no stored key), binds to the provided key and saves.
// Returns true if the key is valid, false if it doesn't match.
// Uses constant-time comparison to prevent timing attacks.
func (s *State) VerifyOrBindClientKey(key string) bool {
	s.mu.Lock()

	// First connection - bind to this client
	if s.clientKey == "" {
		s.clientKey = key
		s.mu.Unlock()
		log.Printf("Bound to client key: %s...", key[:8])
		s.save()
		return true
	}

	// Use constant-time comparison to prevent timing attacks
	match := subtle.ConstantTimeCompare([]byte(s.clientKey), []byte(key)) == 1
	s.mu.Unlock()
	return match
}

// GetClientState returns the current client connection state.
func (s *State) GetClientState() ClientState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.connected {
		return StateConnected
	}
	if s.clientKey != "" {
		return StateDisconnected
	}
	return StateNull
}

// SetClientState updates the client connection state (memory-only).
func (s *State) SetClientState(newState ClientState) {
	s.mu.Lock()
	wasConnected := s.connected
	s.connected = (newState == StateConnected)
	if s.connected && !wasConnected {
		s.stats.ConnectedAt = time.Now()
	} else if !s.connected && wasConnected {
		s.stats.LastDisconnectAt = time.Now()
	}
	s.mu.Unlock()

	if s.connected != wasConnected {
		log.Printf("State changed: client_state=%s", newState)
	}
}

// GetStats returns a copy of the current statistics.
func (s *State) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// RecordRequest increments request count and updates last request time.
func (s *State) RecordRequest() {
	s.mu.Lock()
	s.stats.TotalRequests++
	s.stats.LastRequestAt = time.Now()
	s.mu.Unlock()
}

// AddActiveConn increments active connection count.
func (s *State) AddActiveConn() {
	s.mu.Lock()
	s.stats.ActiveConns++
	s.mu.Unlock()
}

// RemoveActiveConn decrements active connection count.
func (s *State) RemoveActiveConn() {
	s.mu.Lock()
	s.stats.ActiveConns--
	s.mu.Unlock()
}

// AddBytes adds to the byte counters.
func (s *State) AddBytes(in, out int64) {
	s.mu.Lock()
	s.stats.BytesIn += in
	s.stats.BytesOut += out
	s.mu.Unlock()
}

// GetTLSConfig builds a tls.Config from the stored certificate and returns
// the SHA256 fingerprint of the certificate for client verification.
func (s *State) GetTLSConfig() (*tls.Config, string, error) {
	s.mu.RLock()
	certPEM := s.certPEM
	keyPEM := s.keyPEM
	s.mu.RUnlock()

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	fingerprint := computeFingerprint(cert.Certificate[0])
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, fingerprint, nil
}

// generateCert creates a new self-signed RSA certificate valid for 1 year.
func (s *State) generateCert() {
	log.Println("Generating new self-signed certificate...")

	// Use 4096-bit RSA for stronger security
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HA Cloud Tunnel"},
			CommonName:   "HA Cloud Tunnel Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	s.certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	s.keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))

	log.Println("Generated new certificate")
}

// generateToken creates a new random authentication token in "sk-xxxx" format.
func generateToken() string {
	bytes := make([]byte, TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	token := "sk-" + hex.EncodeToString(bytes)
	log.Println("Generated new token")
	return token
}

// computeFingerprint returns the SHA256 fingerprint of a DER-encoded certificate.
func computeFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return "SHA256:" + hex.EncodeToString(hash[:])
}
