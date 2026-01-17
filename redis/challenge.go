package redis

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// ChallengeStoreConfig holds configuration for the Redis challenge store.
type ChallengeStoreConfig struct {
	// Client is the Redis client (required).
	Client Cmdable

	// KeyPrefix is prepended to all Redis keys (default: "attest:challenge:").
	KeyPrefix string

	// Timeout is how long challenges remain valid (default: 5 minutes).
	Timeout time.Duration

	// ChallengeBytes is the number of random bytes in a challenge (default: 32).
	ChallengeBytes int
}

// ChallengeStore is a Redis-backed implementation of challenge.Store.
// Suitable for distributed deployments where multiple server instances
// need to share challenge state.
type ChallengeStore struct {
	client         Cmdable
	keyPrefix      string
	timeout        time.Duration
	challengeBytes int
}

// NewChallengeStore creates a new Redis-backed challenge store.
func NewChallengeStore(cfg ChallengeStoreConfig) (*ChallengeStore, error) {
	if cfg.Client == nil {
		return nil, errors.New("redis client is required")
	}

	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "attest:challenge:"
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	challengeBytes := cfg.ChallengeBytes
	if challengeBytes == 0 {
		challengeBytes = 32
	}

	return &ChallengeStore{
		client:         cfg.Client,
		keyPrefix:      keyPrefix,
		timeout:        timeout,
		challengeBytes: challengeBytes,
	}, nil
}

// Generate creates a new challenge for the given identifier.
func (s *ChallengeStore) Generate(identifier string) (string, error) {
	b := make([]byte, s.challengeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	challenge := base64.RawURLEncoding.EncodeToString(b)
	redisKey := s.keyPrefix + identifier

	// Store with expiration - overwrites any existing challenge
	ctx := context.Background()
	if err := s.client.Set(ctx, redisKey, challenge, s.timeout).Err(); err != nil {
		return "", fmt.Errorf("failed to store challenge: %w", err)
	}

	return challenge, nil
}

// Validate checks if the challenge is valid and consumes it.
// Returns true only if the challenge exists, matches, and hasn't expired.
func (s *ChallengeStore) Validate(identifier, challenge string) bool {
	redisKey := s.keyPrefix + identifier
	ctx := context.Background()

	// Get the stored challenge
	stored, err := s.client.Get(ctx, redisKey).Result()
	if err != nil {
		return false
	}

	// Check if it matches
	if stored != challenge {
		return false
	}

	// Delete the challenge (consume it)
	s.client.Del(ctx, redisKey)

	return true
}

// Close is a no-op for Redis store (connection is managed externally).
func (s *ChallengeStore) Close() {
	// No-op: Redis client lifecycle is managed by the caller
}
