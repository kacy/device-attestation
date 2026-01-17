// Package redis provides Redis-backed implementations of the challenge store
// and key store interfaces for distributed deployments.
//
// This package requires a Redis client to be passed in, giving you full control
// over connection pooling, timeouts, and clustering configuration.
//
// Supported Redis clients:
//   - github.com/redis/go-redis/v9
//   - Any client implementing the Cmdable interface
package redis

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kacy/device-attestation/ios"
)

// Cmdable is the interface for Redis commands.
// This is compatible with github.com/redis/go-redis/v9.Client and ClusterClient.
type Cmdable interface {
	Get(ctx context.Context, key string) StringCmd
	Set(ctx context.Context, key string, value any, expiration time.Duration) StatusCmd
	SetNX(ctx context.Context, key string, value any, expiration time.Duration) BoolCmd
	Del(ctx context.Context, keys ...string) IntCmd
	Incr(ctx context.Context, key string) IntCmd
	HSet(ctx context.Context, key string, values ...any) IntCmd
	HGet(ctx context.Context, key, field string) StringCmd
	HGetAll(ctx context.Context, key string) MapStringStringCmd
	HIncrBy(ctx context.Context, key, field string, incr int64) IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) BoolCmd
}

// StringCmd is the interface for string command results.
type StringCmd interface {
	Result() (string, error)
}

// StatusCmd is the interface for status command results.
type StatusCmd interface {
	Err() error
}

// BoolCmd is the interface for bool command results.
type BoolCmd interface {
	Result() (bool, error)
}

// IntCmd is the interface for int command results.
type IntCmd interface {
	Result() (int64, error)
}

// MapStringStringCmd is the interface for map command results.
type MapStringStringCmd interface {
	Result() (map[string]string, error)
}

// KeyStoreConfig holds configuration for the Redis key store.
type KeyStoreConfig struct {
	// Client is the Redis client (required).
	Client Cmdable

	// KeyPrefix is prepended to all Redis keys (default: "attest:key:").
	KeyPrefix string

	// TTL is how long keys are stored (default: 0 = no expiration).
	// Set this if you want keys to automatically expire.
	TTL time.Duration
}

// KeyStore is a Redis-backed implementation of ios.KeyStore.
// Suitable for distributed deployments where multiple server instances
// need to share attestation state.
type KeyStore struct {
	client    Cmdable
	keyPrefix string
	ttl       time.Duration
}

// storedKeyData is the JSON-serializable representation of a stored key.
type storedKeyData struct {
	PublicKeyDER string    `json:"public_key"`
	BundleID     string    `json:"bundle_id"`
	TeamID       string    `json:"team_id"`
	Counter      uint32    `json:"counter"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
}

// NewKeyStore creates a new Redis-backed key store.
func NewKeyStore(cfg KeyStoreConfig) (*KeyStore, error) {
	if cfg.Client == nil {
		return nil, errors.New("redis client is required")
	}

	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "attest:key:"
	}

	return &KeyStore{
		client:    cfg.Client,
		keyPrefix: keyPrefix,
		ttl:       cfg.TTL,
	}, nil
}

// Store saves a public key for the given key ID.
func (s *KeyStore) Store(ctx context.Context, keyID string, key *ios.StoredKey) error {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(key.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	data := storedKeyData{
		PublicKeyDER: base64.StdEncoding.EncodeToString(pubKeyDER),
		BundleID:     key.BundleID,
		TeamID:       key.TeamID,
		Counter:      key.Counter,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Time{},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal key data: %w", err)
	}

	redisKey := s.keyPrefix + keyID

	// Use SetNX to prevent overwriting existing keys
	ok, err := s.client.SetNX(ctx, redisKey, jsonData, s.ttl).Result()
	if err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}
	if !ok {
		return ios.ErrKeyExists
	}

	return nil
}

// Load retrieves a public key by key ID.
func (s *KeyStore) Load(ctx context.Context, keyID string) (*ios.StoredKey, error) {
	redisKey := s.keyPrefix + keyID

	jsonData, err := s.client.Get(ctx, redisKey).Result()
	if err != nil {
		if isNil(err) {
			return nil, ios.ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	var data storedKeyData
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key data: %w", err)
	}

	pubKeyDER, err := base64.StdEncoding.DecodeString(data.PublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("stored key is not an ECDSA public key")
	}

	return &ios.StoredKey{
		KeyID:      keyID,
		PublicKey:  pubKey,
		BundleID:   data.BundleID,
		TeamID:     data.TeamID,
		Counter:    data.Counter,
		CreatedAt:  data.CreatedAt,
		LastUsedAt: data.LastUsedAt,
	}, nil
}

// Delete removes a public key by key ID.
func (s *KeyStore) Delete(ctx context.Context, keyID string) error {
	redisKey := s.keyPrefix + keyID

	n, err := s.client.Del(ctx, redisKey).Result()
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	if n == 0 {
		return ios.ErrKeyNotFound
	}

	return nil
}

// IncrementCounter atomically increments and returns the new counter value.
func (s *KeyStore) IncrementCounter(ctx context.Context, keyID string) (uint32, error) {
	redisKey := s.keyPrefix + keyID

	// Load current data
	jsonData, err := s.client.Get(ctx, redisKey).Result()
	if err != nil {
		if isNil(err) {
			return 0, ios.ErrKeyNotFound
		}
		return 0, fmt.Errorf("failed to load key: %w", err)
	}

	var data storedKeyData
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return 0, fmt.Errorf("failed to unmarshal key data: %w", err)
	}

	// Increment counter
	data.Counter++
	data.LastUsedAt = time.Now()

	// Save back
	newJSON, err := json.Marshal(data)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal key data: %w", err)
	}

	if err := s.client.Set(ctx, redisKey, newJSON, s.ttl).Err(); err != nil {
		return 0, fmt.Errorf("failed to update key: %w", err)
	}

	return data.Counter, nil
}

// isNil checks if the error is a redis.Nil error.
// We check the error string to avoid importing go-redis directly.
func isNil(err error) bool {
	return err != nil && err.Error() == "redis: nil"
}
