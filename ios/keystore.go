package ios

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"sync"
	"time"
)

// KeyStore defines the interface for storing and retrieving attestation public keys.
// Implementations should be thread-safe.
type KeyStore interface {
	// Store saves a public key for the given key ID.
	Store(ctx context.Context, keyID string, key *StoredKey) error

	// Load retrieves a public key by key ID.
	Load(ctx context.Context, keyID string) (*StoredKey, error)

	// Delete removes a public key by key ID.
	Delete(ctx context.Context, keyID string) error

	// IncrementCounter atomically increments and returns the new counter value.
	IncrementCounter(ctx context.Context, keyID string) (uint32, error)
}

// StoredKey represents a stored attestation public key with metadata.
type StoredKey struct {
	// KeyID is the unique identifier for this key.
	KeyID string

	// PublicKey is the ECDSA public key from the attestation.
	PublicKey *ecdsa.PublicKey

	// BundleID is the app bundle identifier associated with this key.
	BundleID string

	// TeamID is the Apple Team ID.
	TeamID string

	// Counter is the assertion counter for replay protection.
	Counter uint32

	// CreatedAt is when the key was first attested.
	CreatedAt time.Time

	// LastUsedAt is when the key was last used for an assertion.
	LastUsedAt time.Time
}

// Common errors for KeyStore implementations.
var (
	ErrKeyNotFound = errors.New("key not found")
	ErrKeyExists   = errors.New("key already exists")
)

// MemoryKeyStore is an in-memory implementation of KeyStore.
// Suitable for testing and development. For production, use a persistent store.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*StoredKey
}

// NewMemoryKeyStore creates a new in-memory key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys: make(map[string]*StoredKey),
	}
}

// Store saves a public key for the given key ID.
func (s *MemoryKeyStore) Store(ctx context.Context, keyID string, key *StoredKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[keyID]; exists {
		return ErrKeyExists
	}

	keyCopy := *key
	keyCopy.KeyID = keyID
	keyCopy.CreatedAt = time.Now()
	s.keys[keyID] = &keyCopy
	return nil
}

// Load retrieves a public key by key ID.
func (s *MemoryKeyStore) Load(ctx context.Context, keyID string) (*StoredKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	keyCopy := *key
	return &keyCopy, nil
}

// Delete removes a public key by key ID.
func (s *MemoryKeyStore) Delete(ctx context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[keyID]; !exists {
		return ErrKeyNotFound
	}

	delete(s.keys, keyID)
	return nil
}

// IncrementCounter atomically increments and returns the new counter value.
func (s *MemoryKeyStore) IncrementCounter(ctx context.Context, keyID string) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keys[keyID]
	if !exists {
		return 0, ErrKeyNotFound
	}

	key.Counter++
	key.LastUsedAt = time.Now()
	return key.Counter, nil
}
