package main

import (
	"crypto/sha256"
	"encoding/hex"
)

// DeriveClientKey generates a deterministic client key from the token and fingerprint.
// This uniquely identifies this client/server pair without needing persistent storage.
func DeriveClientKey(token, fingerprint string) string {
	h := sha256.New()
	h.Write([]byte("ha-cloud-tunnel-client-key:"))
	h.Write([]byte(token))
	h.Write([]byte(":"))
	h.Write([]byte(fingerprint))
	return "ck-" + hex.EncodeToString(h.Sum(nil))
}
