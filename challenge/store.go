// Package challenge provides secure challenge generation and validation
// for device attestation flows.
//
// Challenges are cryptographically random tokens that must be signed by
// the device to prove the attestation was performed in response to a
// specific server request (prevents replay attacks).
package challenge

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Store manages attestation challenges with automatic expiration.
type Store interface {
	// Generate creates a new challenge for the given identifier.
	// The identifier is typically a user ID or session ID.
	Generate(identifier string) (string, error)

	// Validate checks if the challenge is valid and consumes it.
	// Returns true only if the challenge exists, matches, and hasn't expired.
	Validate(identifier, challenge string) bool

	// Close stops background cleanup routines.
	Close()
}

// Config holds configuration for the challenge store.
type Config struct {
	// Timeout is how long challenges remain valid (default: 5 minutes).
	Timeout time.Duration

	// CleanupInterval is how often expired challenges are removed (default: 1 minute).
	CleanupInterval time.Duration

	// ChallengeBytes is the number of random bytes in a challenge (default: 32).
	ChallengeBytes int
}

type challengeEntry struct {
	challenge string
	expiresAt time.Time
}

// MemoryStore is an in-memory implementation of Store.
// Suitable for single-instance deployments. For distributed systems,
// use a Redis or database-backed implementation.
type MemoryStore struct {
	mu             sync.RWMutex
	store          map[string]challengeEntry
	timeout        time.Duration
	challengeBytes int
	closeCh        chan struct{}
	closed         bool
}

// NewMemoryStore creates a new in-memory challenge store.
func NewMemoryStore(cfg Config) *MemoryStore {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	cleanupInterval := cfg.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = time.Minute
	}

	challengeBytes := cfg.ChallengeBytes
	if challengeBytes == 0 {
		challengeBytes = 32
	}

	cs := &MemoryStore{
		store:          make(map[string]challengeEntry),
		timeout:        timeout,
		challengeBytes: challengeBytes,
		closeCh:        make(chan struct{}),
	}

	go cs.cleanupLoop(cleanupInterval)

	return cs
}

// Generate creates a cryptographically secure random challenge.
func (s *MemoryStore) Generate(identifier string) (string, error) {
	b := make([]byte, s.challengeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	challenge := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	s.store[identifier] = challengeEntry{
		challenge: challenge,
		expiresAt: time.Now().Add(s.timeout),
	}
	s.mu.Unlock()

	return challenge, nil
}

// Validate checks if the challenge matches and hasn't expired.
// The challenge is consumed only on successful validation.
func (s *MemoryStore) Validate(identifier, challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.store[identifier]
	if !exists {
		return false
	}

	if time.Now().After(entry.expiresAt) {
		delete(s.store, identifier)
		return false
	}

	if entry.challenge != challenge {
		return false
	}

	// Only delete on successful validation
	delete(s.store, identifier)
	return true
}

// Close stops the background cleanup goroutine.
func (s *MemoryStore) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	close(s.closeCh)
}

func (s *MemoryStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.closeCh:
			return
		}
	}
}

func (s *MemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for identifier, entry := range s.store {
		if now.After(entry.expiresAt) {
			delete(s.store, identifier)
		}
	}
}

// Len returns the number of active challenges (for testing/monitoring).
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.store)
}
