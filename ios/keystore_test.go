package ios

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) *ecdsa.PublicKey {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &privKey.PublicKey
}

func TestMemoryKeyStore_StoreAndLoad(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()
	pubKey := generateTestKey(t)

	storedKey := &StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err := store.Store(ctx, "key-123", storedKey)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, "key-123")
	require.NoError(t, err)
	assert.Equal(t, "key-123", loaded.KeyID)
	assert.Equal(t, "com.example.app", loaded.BundleID)
	assert.Equal(t, "TEAM123", loaded.TeamID)
	assert.Equal(t, uint32(0), loaded.Counter)
	assert.NotZero(t, loaded.CreatedAt)
}

func TestMemoryKeyStore_StoreKeyExists(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()
	pubKey := generateTestKey(t)

	storedKey := &StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err := store.Store(ctx, "key-123", storedKey)
	require.NoError(t, err)

	err = store.Store(ctx, "key-123", storedKey)
	assert.ErrorIs(t, err, ErrKeyExists)
}

func TestMemoryKeyStore_LoadNotFound(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()

	_, err := store.Load(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestMemoryKeyStore_Delete(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()
	pubKey := generateTestKey(t)

	storedKey := &StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err := store.Store(ctx, "key-123", storedKey)
	require.NoError(t, err)

	err = store.Delete(ctx, "key-123")
	require.NoError(t, err)

	_, err = store.Load(ctx, "key-123")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestMemoryKeyStore_DeleteNotFound(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()

	err := store.Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestMemoryKeyStore_IncrementCounter(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()
	pubKey := generateTestKey(t)

	storedKey := &StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err := store.Store(ctx, "key-123", storedKey)
	require.NoError(t, err)

	counter, err := store.IncrementCounter(ctx, "key-123")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), counter)

	counter, err = store.IncrementCounter(ctx, "key-123")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), counter)

	counter, err = store.IncrementCounter(ctx, "key-123")
	require.NoError(t, err)
	assert.Equal(t, uint32(3), counter)

	// Verify counter persisted
	loaded, err := store.Load(ctx, "key-123")
	require.NoError(t, err)
	assert.Equal(t, uint32(3), loaded.Counter)
}

func TestMemoryKeyStore_IncrementCounterNotFound(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()

	_, err := store.IncrementCounter(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestMemoryKeyStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()
	pubKey := generateTestKey(t)

	storedKey := &StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err := store.Store(ctx, "key-123", storedKey)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.IncrementCounter(ctx, "key-123")
		}()
	}
	wg.Wait()

	loaded, err := store.Load(ctx, "key-123")
	require.NoError(t, err)
	assert.Equal(t, uint32(100), loaded.Counter)
}

func TestMemoryKeyStore_IsolatedCopies(t *testing.T) {
	store := NewMemoryKeyStore()
	ctx := context.Background()
	pubKey := generateTestKey(t)

	storedKey := &StoredKey{
		PublicKey: pubKey,
		BundleID:  "com.example.app",
		TeamID:    "TEAM123",
	}

	err := store.Store(ctx, "key-123", storedKey)
	require.NoError(t, err)

	loaded1, _ := store.Load(ctx, "key-123")
	loaded2, _ := store.Load(ctx, "key-123")

	// Modifying one copy shouldn't affect the other
	loaded1.BundleID = "modified"
	assert.NotEqual(t, loaded1.BundleID, loaded2.BundleID)
}
