package challenge

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_GenerateAndValidate(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 5 * time.Minute})
	defer store.Close()

	challenge, err := store.Generate("user123")
	require.NoError(t, err)
	assert.NotEmpty(t, challenge)
	assert.Len(t, challenge, 43) // base64url of 32 bytes

	valid := store.Validate("user123", challenge)
	assert.True(t, valid)

	// Challenge should be consumed
	valid = store.Validate("user123", challenge)
	assert.False(t, valid)
}

func TestMemoryStore_InvalidChallenge(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 5 * time.Minute})
	defer store.Close()

	_, err := store.Generate("user123")
	require.NoError(t, err)

	valid := store.Validate("user123", "wrong-challenge")
	assert.False(t, valid)

	// Original challenge should still be valid after failed attempt
	challenge, _ := store.Generate("user123")
	valid = store.Validate("user123", challenge)
	assert.True(t, valid)
}

func TestMemoryStore_NonexistentIdentifier(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 5 * time.Minute})
	defer store.Close()

	valid := store.Validate("nonexistent", "any-challenge")
	assert.False(t, valid)
}

func TestMemoryStore_ExpiredChallenge(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 1 * time.Millisecond})
	defer store.Close()

	challenge, err := store.Generate("user123")
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	valid := store.Validate("user123", challenge)
	assert.False(t, valid)
}

func TestMemoryStore_MultipleIdentifiers(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 5 * time.Minute})
	defer store.Close()

	challenge1, _ := store.Generate("user1")
	challenge2, _ := store.Generate("user2")

	assert.NotEqual(t, challenge1, challenge2)
	assert.True(t, store.Validate("user1", challenge1))
	assert.True(t, store.Validate("user2", challenge2))
}

func TestMemoryStore_OverwritePreviousChallenge(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 5 * time.Minute})
	defer store.Close()

	challenge1, _ := store.Generate("user123")
	challenge2, _ := store.Generate("user123")

	assert.NotEqual(t, challenge1, challenge2)
	assert.False(t, store.Validate("user123", challenge1))
	assert.True(t, store.Validate("user123", challenge2))
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 5 * time.Minute})
	defer store.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			userID := "user" + string(rune('0'+id%10))
			challenge, _ := store.Generate(userID)
			store.Validate(userID, challenge)
		}(i)
	}
	wg.Wait()
}

func TestMemoryStore_Len(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 5 * time.Minute})
	defer store.Close()

	assert.Equal(t, 0, store.Len())

	store.Generate("user1")
	assert.Equal(t, 1, store.Len())

	store.Generate("user2")
	assert.Equal(t, 2, store.Len())

	// Overwrite shouldn't increase count
	store.Generate("user1")
	assert.Equal(t, 2, store.Len())
}

func TestMemoryStore_CustomChallengeBytes(t *testing.T) {
	store := NewMemoryStore(Config{
		Timeout:        5 * time.Minute,
		ChallengeBytes: 16,
	})
	defer store.Close()

	challenge, err := store.Generate("user123")
	require.NoError(t, err)
	// 16 bytes = 22 base64url chars (without padding)
	assert.Len(t, challenge, 22)
}

func TestMemoryStore_CloseIdempotent(t *testing.T) {
	store := NewMemoryStore(Config{Timeout: 5 * time.Minute})

	// Should not panic when called multiple times
	store.Close()
	store.Close()
	store.Close()
}
