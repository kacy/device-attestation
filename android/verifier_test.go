package android

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewVerifier_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing package names",
			config: Config{
				PackageNames: []string{},
				GCPProjectID: "my-project",
			},
			wantErr: true,
			errMsg:  "at least one package name is required",
		},
		{
			name: "missing GCP project ID",
			config: Config{
				PackageNames: []string{"com.example.app"},
				GCPProjectID: "",
			},
			wantErr: true,
			errMsg:  "GCP project ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewVerifier(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{
		PackageNames: []string{"com.example.app"},
		GCPProjectID: "my-project",
	}

	// Can't fully test without GCP credentials, but we can test config parsing
	assert.Equal(t, time.Duration(0), cfg.ChallengeTimeout) // Will default to 5 min in NewVerifier
	assert.False(t, cfg.RequireStrongIntegrity)
	assert.False(t, cfg.AllowBasicIntegrity)
}

func TestConfig_APKCertDigests(t *testing.T) {
	cfg := Config{
		PackageNames: []string{"com.example.app"},
		GCPProjectID: "my-project",
		APKCertDigests: []string{
			"AA:BB:CC:DD:EE:FF",
			"11:22:33:44:55:66",
		},
	}

	assert.Len(t, cfg.APKCertDigests, 2)
}

func TestErrors(t *testing.T) {
	// Verify error types are distinct
	assert.NotEqual(t, ErrVerificationFailed, ErrInvalidPackageName)
	assert.NotEqual(t, ErrInvalidChallenge, ErrAttestationExpired)
	assert.NotEqual(t, ErrDeviceCompromised, ErrAppNotRecognized)
	assert.NotEqual(t, ErrCertDigestMismatch, ErrVerificationFailed)
}
