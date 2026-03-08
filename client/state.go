package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"sync"
)

const (
	StateDir      = "/data"
	StateFile     = "/data/state.json"
	ClientKeyLen  = 16 // 16 bytes = 32 hex chars
)

// persistedState is the data saved to disk.
type persistedState struct {
	ClientKey string `json:"client_key"`
}

// ClientState holds client credentials that persist across restarts.
type ClientState struct {
	clientKey string
	mu        sync.RWMutex
}

var clientStateInstance *ClientState
var clientStateOnce sync.Once

// GetClientState returns the singleton ClientState instance.
// On first call, loads credentials from disk or creates new ones.
func GetClientState() *ClientState {
	clientStateOnce.Do(func() {
		clientStateInstance = &ClientState{}

		// Ensure data directory exists
		if err := os.MkdirAll(StateDir, 0777); err != nil {
			log.Printf("Warning: could not create data directory: %v", err)
		}

		if err := clientStateInstance.load(); err != nil {
			log.Printf("Creating new client key: %v", err)
			clientStateInstance.clientKey = generateClientKey()
			clientStateInstance.save()
		}
	})
	return clientStateInstance
}

// load reads credentials from the state file.
func (s *ClientState) load() error {
	data, err := os.ReadFile(StateFile)
	if err != nil {
		return err
	}

	var p persistedState
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}

	// Validate client key format: "ck-" + 32 hex chars = 35 total
	if len(p.ClientKey) != 35 || p.ClientKey[:3] != "ck-" {
		return os.ErrInvalid
	}

	s.mu.Lock()
	s.clientKey = p.ClientKey
	s.mu.Unlock()

	log.Printf("Loaded client key from disk: %s...", p.ClientKey[:8])
	return nil
}

// save writes credentials to the state file.
func (s *ClientState) save() error {
	s.mu.RLock()
	p := persistedState{
		ClientKey: s.clientKey,
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(StateFile, data, 0600); err != nil {
		log.Printf("Warning: could not save client state: %v", err)
		return err
	}

	log.Printf("Saved client key: %s...", p.ClientKey[:8])
	return nil
}

// GetClientKey returns the client key.
func (s *ClientState) GetClientKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientKey
}

// generateClientKey creates a new random client key in "ck-xxxx" format.
func generateClientKey() string {
	bytes := make([]byte, ClientKeyLen)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate client key: %v", err)
	}
	return "ck-" + hex.EncodeToString(bytes)
}
