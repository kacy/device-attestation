package ios

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerifier_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: Config{
				BundleIDs: []string{"com.example.app"},
				TeamID:    "TEAM123456",
			},
			wantErr: false,
		},
		{
			name: "missing bundle IDs",
			config: Config{
				BundleIDs: []string{},
				TeamID:    "TEAM123456",
			},
			wantErr: true,
			errMsg:  "at least one bundle ID is required",
		},
		{
			name: "missing team ID",
			config: Config{
				BundleIDs: []string{"com.example.app"},
				TeamID:    "",
			},
			wantErr: true,
			errMsg:  "team ID is required",
		},
		{
			name: "multiple bundle IDs",
			config: Config{
				BundleIDs: []string{"com.example.app", "com.example.app.dev"},
				TeamID:    "TEAM123456",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, v)
			}
		})
	}
}

func TestVerifier_VerifyAttestation_InvalidBundleID(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)

	_, err = v.VerifyAttestation(context.Background(), &AttestationRequest{
		Attestation: "dGVzdA==",
		Challenge:   "test-challenge",
		KeyID:       "test-key-id",
		BundleID:    "com.other.app",
	})
	assert.ErrorIs(t, err, ErrInvalidBundleID)
}

func TestVerifier_VerifyAttestation_MissingKeyID(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)

	_, err = v.VerifyAttestation(context.Background(), &AttestationRequest{
		Attestation: "dGVzdA==",
		Challenge:   "test-challenge",
		KeyID:       "",
		BundleID:    "com.example.app",
	})
	assert.ErrorIs(t, err, ErrInvalidKeyID)
}

func TestVerifier_VerifyAttestation_InvalidBase64(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)

	_, err = v.VerifyAttestation(context.Background(), &AttestationRequest{
		Attestation: "not-valid-base64!!!",
		Challenge:   "test-challenge",
		KeyID:       "test-key-id",
		BundleID:    "com.example.app",
	})
	assert.ErrorIs(t, err, ErrInvalidAttestation)
}

func TestVerifier_VerifyAssertion_NoKeyStore(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)

	_, err = v.VerifyAssertion(context.Background(), &AssertionRequest{
		Assertion:  "dGVzdA==",
		ClientData: []byte("test"),
		KeyID:      "test-key-id",
		BundleID:   "com.example.app",
	})
	assert.ErrorIs(t, err, ErrKeyStoreRequired)
}

func TestVerifier_VerifyAssertion_KeyNotFound(t *testing.T) {
	keyStore := NewMemoryKeyStore()
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
		KeyStore:  keyStore,
	})
	require.NoError(t, err)

	_, err = v.VerifyAssertion(context.Background(), &AssertionRequest{
		Assertion:  "dGVzdA==",
		ClientData: []byte("test"),
		KeyID:      "nonexistent-key",
		BundleID:   "com.example.app",
	})
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestVerifier_DefaultTimeout(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs: []string{"com.example.app"},
		TeamID:    "TEAM123456",
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, v.timeout)
}

func TestVerifier_CustomTimeout(t *testing.T) {
	v, err := NewVerifier(Config{
		BundleIDs:        []string{"com.example.app"},
		TeamID:           "TEAM123456",
		ChallengeTimeout: 10 * time.Minute,
	})
	require.NoError(t, err)
	assert.Equal(t, 10*time.Minute, v.timeout)
}
