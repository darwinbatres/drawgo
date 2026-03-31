package jwt

import (
	"sync"
	"time"
)

// Blacklist is an in-memory set of revoked JWT token IDs (jti claims) or raw
// token hashes. Entries auto-expire after the configured TTL to keep memory
// bounded. This provides immediate access-token revocation on logout without
// requiring a database round-trip on every request.
type Blacklist struct {
	mu      sync.RWMutex
	entries map[string]time.Time // token identifier → expiry time
	ttl     time.Duration
}

// NewBlacklist creates a Blacklist that holds entries for the given TTL.
// Typically set to the access token lifetime (e.g. 15 minutes).
func NewBlacklist(ttl time.Duration) *Blacklist {
	bl := &Blacklist{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
	go bl.cleanup()
	return bl
}

// Add marks a token identifier as revoked.
func (bl *Blacklist) Add(tokenID string) {
	bl.mu.Lock()
	bl.entries[tokenID] = time.Now().Add(bl.ttl)
	bl.mu.Unlock()
}

// IsBlacklisted returns true if the token identifier has been revoked.
func (bl *Blacklist) IsBlacklisted(tokenID string) bool {
	bl.mu.RLock()
	expiry, ok := bl.entries[tokenID]
	bl.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Now().Before(expiry)
}

// cleanup periodically evicts expired entries to prevent memory growth.
func (bl *Blacklist) cleanup() {
	ticker := time.NewTicker(bl.ttl)
	defer ticker.Stop()
	for range ticker.C {
		bl.mu.Lock()
		now := time.Now()
		for id, exp := range bl.entries {
			if now.After(exp) {
				delete(bl.entries, id)
			}
		}
		bl.mu.Unlock()
	}
}
