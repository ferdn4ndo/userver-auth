package lib

import (
	"crypto/sha256"
	"crypto/subtle"
)

// SecretsEqual compares two secret strings in constant time (via SHA-256 digests).
func SecretsEqual(a, b string) bool {
	sa := sha256.Sum256([]byte(a))
	sb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(sa[:], sb[:]) == 1
}
