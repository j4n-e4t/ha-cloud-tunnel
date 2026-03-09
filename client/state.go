package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// DeriveClientKey generates a deterministic client key from the machine identity.
// Uses /etc/machine-id (Linux/systemd) or hostname as fallback.
func DeriveClientKey() string {
	machineID := getMachineID()

	h := sha256.New()
	h.Write([]byte("ha-cloud-tunnel-client-key:"))
	h.Write([]byte(machineID))
	return "ck-" + hex.EncodeToString(h.Sum(nil))
}

// getMachineID returns a unique identifier for this machine.
func getMachineID() string {
	// Try /etc/machine-id (Linux/systemd)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		return strings.TrimSpace(string(data))
	}

	// Try /var/lib/dbus/machine-id (older systems)
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return strings.TrimSpace(string(data))
	}

	// Fallback to hostname
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}

	return "unknown"
}
