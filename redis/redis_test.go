package redis

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kacy/device-attestation/ios"
)

// mockRedis is a simple in-memory mock of Redis for testing.
type mockRedis struct {
	mu   sync.RWMutex
	data map[string]mockEntry
}

type mockEntry struct {
	value     string
	expiresAt time.Time
}

func newMockRedis() *mockRedis {
	return &mockRedis{
		data: make(map[string]mockEntry),
	}
}

func (m *mockRedis) Get(ctx context.Context, key string) StringCmd {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.data[key]
	if !ok || (!entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt)) {
		return &mockStringCmd{err: mockNilErr}
	}
	return &mockStringCmd{val: entry.value}
}

func (m *mockRedis) Set(ctx context.Context, key string, value any, expiration time.Duration) StatusCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expiresAt time.Time
	if expiration > 0 {
		expiresAt = time.Now().Add(expiration)
	}

	m.data[key] = mockEntry{
		value:     toString(value),
		expiresAt: expiresAt,
	}
	return &mockStatusCmd{}
}

func (m *mockRedis) SetNX(ctx context.Context, key string, value any, expiration time.Duration) BoolCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.data[key]; exists {
		return &mockBoolCmd{val: false}
	}

	var expiresAt time.Time
	if expiration > 0 {
		expiresAt = time.Now().Add(expiration)
	}

	m.data[key] = mockEntry{
		value:     toString(value),
		expiresAt: expiresAt,
	}
	return &mockBoolCmd{val: true}
}

func toString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	default:
		return ""
	}
}

func (m *mockRedis) Del(ctx context.Context, keys ...string) IntCmd {
	m.mu.Lock()
	defer m.mu.Unlock()

	var deleted int64
	for _, key := range keys {
		if _, exists := m.data[key]; exists {
			delete(m.data, key)
			deleted++
		}
	}
	return &mockIntCmd{val: deleted}
}

func (m *mockRedis) Incr(ctx context.Context, key string) IntCmd {
	return &mockIntCmd{val: 1}
}

func (m *mockRedis) HSet(ctx context.Context, key string, values ...any) IntCmd {
	return &mockIntCmd{val: 1}
}

func (m *mockRedis) HGet(ctx context.Context, key, field string) StringCmd {
	return &mockStringCmd{}
}

func (m *mockRedis) HGetAll(ctx context.Context, key string) MapStringStringCmd {
	return &mockMapCmd{val: make(map[string]string)}
}

func (m *mockRedis) HIncrBy(ctx context.Context, key, field string, incr int64) IntCmd {
	return &mockIntCmd{val: incr}
}

func (m *mockRedis) Expire(ctx context.Context, key string, expiration time.Duration) BoolCmd {
	return &mockBoolCmd{val: true}
}

// Mock command implementations
type mockNilError struct{}

func (e mockNilError) Error() string { return "redis: nil" }

var mockNilErr = mockNilError{}

type mockStringCmd struct {
	val string
	err error
}

func (c *mockStringCmd) Result() (string, error) { return c.val, c.err }

type mockStatusCmd struct {
	err error
}

func (c *mockStatusCmd) Err() error { return c.err }

type mockBoolCmd struct {
	val bool
	err error
}

func (c *mockBoolCmd) Result() (bool, error) { return c.val, c.err }

type mockIntCmd struct {
	val int64
	err error
}

func (c *mockIntCmd) Result() (int64, error) { return c.val, c.err }

type mockMapCmd struct {
	val map[string]string
	err error
}

func (c *mockMapCmd) Result() (map[string]string, error) { return c.val, c.err }

// Tests

func TestNewChallengeStore_Validation(t *testing.T) {
	_, err := NewChallengeStore(ChallengeStoreConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is required")

	store, err := NewChallengeStore(ChallengeStoreConfig{
		Client: newMockRedis(),
	})
	assert.NoError(t, err)
	assert.NotNil(t, store)
}

func TestChallengeStore_GenerateAndValidate(t *testing.T) {
	store, err := NewChallengeStore(ChallengeStoreConfig{
		Client:  newMockRedis(),
		Timeout: 5 * time.Minute,
	})
	require.NoError(t, err)

	challenge, err := store.Generate("user-123")
	require.NoError(t, err)
	assert.NotEmpty(t, challenge)
	assert.Len(t, challenge, 43) // base64url of 32 bytes

	// Valid challenge
	assert.True(t, store.Validate("user-123", challenge))

	// Challenge consumed
	assert.False(t, store.Validate("user-123", challenge))
}

func TestChallengeStore_InvalidChallenge(t *testing.T) {
	store, err := NewChallengeStore(ChallengeStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	store.Generate("user-123")
	assert.False(t, store.Validate("user-123", "wrong-challenge"))
}

func TestChallengeStore_NonexistentUser(t *testing.T) {
	store, err := NewChallengeStore(ChallengeStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	assert.False(t, store.Validate("nonexistent", "any-challenge"))
}

func TestChallengeStore_Close(t *testing.T) {
	store, err := NewChallengeStore(ChallengeStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	// Should not panic
	store.Close()
	store.Close()
}

func TestNewKeyStore_Validation(t *testing.T) {
	_, err := NewKeyStore(KeyStoreConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis client is required")

	store, err := NewKeyStore(KeyStoreConfig{
		Client: newMockRedis(),
	})
	assert.NoError(t, err)
	assert.NotNil(t, store)
}

func generateTestKey(t *testing.T) *ecdsa.PublicKey {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &privKey.PublicKey
}

func TestKeyStore_StoreAndLoad(t *testing.T) {
	store, err := NewKeyStore(KeyStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	pubKey := generateTestKey(t)
	storedKey := &ios.StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err = store.Store(context.Background(), "key-123", storedKey)
	require.NoError(t, err)

	loaded, err := store.Load(context.Background(), "key-123")
	require.NoError(t, err)
	assert.Equal(t, "key-123", loaded.KeyID)
	assert.Equal(t, "com.example.app", loaded.BundleID)
	assert.Equal(t, "TEAM123", loaded.TeamID)
}

func TestKeyStore_StoreKeyExists(t *testing.T) {
	store, err := NewKeyStore(KeyStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	pubKey := generateTestKey(t)
	storedKey := &ios.StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err = store.Store(context.Background(), "key-123", storedKey)
	require.NoError(t, err)

	err = store.Store(context.Background(), "key-123", storedKey)
	assert.ErrorIs(t, err, ios.ErrKeyExists)
}

func TestKeyStore_LoadNotFound(t *testing.T) {
	store, err := NewKeyStore(KeyStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	_, err = store.Load(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ios.ErrKeyNotFound)
}

func TestKeyStore_Delete(t *testing.T) {
	store, err := NewKeyStore(KeyStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	pubKey := generateTestKey(t)
	storedKey := &ios.StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err = store.Store(context.Background(), "key-123", storedKey)
	require.NoError(t, err)

	err = store.Delete(context.Background(), "key-123")
	require.NoError(t, err)

	_, err = store.Load(context.Background(), "key-123")
	assert.ErrorIs(t, err, ios.ErrKeyNotFound)
}

func TestKeyStore_DeleteNotFound(t *testing.T) {
	store, err := NewKeyStore(KeyStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	err = store.Delete(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ios.ErrKeyNotFound)
}

func TestKeyStore_IncrementCounter(t *testing.T) {
	store, err := NewKeyStore(KeyStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	pubKey := generateTestKey(t)
	storedKey := &ios.StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err = store.Store(context.Background(), "key-123", storedKey)
	require.NoError(t, err)

	counter, err := store.IncrementCounter(context.Background(), "key-123")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), counter)

	counter, err = store.IncrementCounter(context.Background(), "key-123")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), counter)
}

func TestKeyStore_IncrementCounterNotFound(t *testing.T) {
	store, err := NewKeyStore(KeyStoreConfig{
		Client: newMockRedis(),
	})
	require.NoError(t, err)

	_, err = store.IncrementCounter(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ios.ErrKeyNotFound)
}
