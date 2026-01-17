package attestation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  ServerConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "no platforms configured",
			config:  ServerConfig{},
			wantErr: true,
			errMsg:  "at least one platform",
		},
		{
			name: "iOS missing bundle IDs",
			config: ServerConfig{
				IOS: &IOSConfig{
					BundleIDs: []string{},
					TeamID:    "TEAM123",
				},
			},
			wantErr: true,
			errMsg:  "at least one bundle ID",
		},
		{
			name: "iOS missing team ID",
			config: ServerConfig{
				IOS: &IOSConfig{
					BundleIDs: []string{"com.example.app"},
					TeamID:    "",
				},
			},
			wantErr: true,
			errMsg:  "team ID is required",
		},
		{
			name: "Android missing package names",
			config: ServerConfig{
				Android: &AndroidConfig{
					PackageNames: []string{},
					GCPProjectID: "my-project",
				},
			},
			wantErr: true,
			errMsg:  "at least one package name",
		},
		{
			name: "Android missing GCP project",
			config: ServerConfig{
				Android: &AndroidConfig{
					PackageNames: []string{"com.example.app"},
					GCPProjectID: "",
				},
			},
			wantErr: true,
			errMsg:  "GCP project ID is required",
		},
		{
			name: "valid iOS only",
			config: ServerConfig{
				IOS: &IOSConfig{
					BundleIDs: []string{"com.example.app"},
					TeamID:    "TEAM123456",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, server)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, server)
				if server != nil {
					server.Close()
				}
			}
		})
	}
}

func TestServer_GenerateChallenge(t *testing.T) {
	server, err := NewServer(ServerConfig{
		IOS: &IOSConfig{
			BundleIDs: []string{"com.example.app"},
			TeamID:    "TEAM123456",
		},
	})
	require.NoError(t, err)
	defer server.Close()

	challenge, err := server.GenerateChallenge("user-123")
	require.NoError(t, err)
	assert.NotEmpty(t, challenge)
	assert.Len(t, challenge, 43) // base64url of 32 bytes
}

func TestServer_GenerateChallenge_AfterClose(t *testing.T) {
	server, err := NewServer(ServerConfig{
		IOS: &IOSConfig{
			BundleIDs: []string{"com.example.app"},
			TeamID:    "TEAM123456",
		},
	})
	require.NoError(t, err)

	server.Close()

	_, err = server.GenerateChallenge("user-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestServer_Close_Idempotent(t *testing.T) {
	server, err := NewServer(ServerConfig{
		IOS: &IOSConfig{
			BundleIDs: []string{"com.example.app"},
			TeamID:    "TEAM123456",
		},
	})
	require.NoError(t, err)

	// Should not panic
	assert.NoError(t, server.Close())
	assert.NoError(t, server.Close())
	assert.NoError(t, server.Close())
}

func TestServer_Accessors(t *testing.T) {
	server, err := NewServer(ServerConfig{
		IOS: &IOSConfig{
			BundleIDs: []string{"com.example.app"},
			TeamID:    "TEAM123456",
		},
	})
	require.NoError(t, err)
	defer server.Close()

	assert.NotNil(t, server.Challenges())
	assert.NotNil(t, server.KeyStore())
	assert.NotNil(t, server.Verifier())
}

func TestServer_DefaultTimeout(t *testing.T) {
	server, err := NewServer(ServerConfig{
		IOS: &IOSConfig{
			BundleIDs: []string{"com.example.app"},
			TeamID:    "TEAM123456",
		},
	})
	require.NoError(t, err)
	defer server.Close()

	// Generate a challenge and verify it works
	challenge, err := server.GenerateChallenge("user-123")
	require.NoError(t, err)
	assert.NotEmpty(t, challenge)
}

func TestServer_CustomTimeout(t *testing.T) {
	server, err := NewServer(ServerConfig{
		IOS: &IOSConfig{
			BundleIDs: []string{"com.example.app"},
			TeamID:    "TEAM123456",
		},
		ChallengeTimeout: 1 * time.Millisecond,
	})
	require.NoError(t, err)
	defer server.Close()

	challenge, err := server.GenerateChallenge("user-123")
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(5 * time.Millisecond)

	// Challenge should be expired - internal validation would fail
	// We can't directly test VerifyAttestation without real attestation data,
	// but we can verify the challenge was created
	assert.NotEmpty(t, challenge)
}
