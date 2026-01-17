package attestation

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kacy/device-attestation/challenge"
	"github.com/kacy/device-attestation/ios"
)

// Server provides a batteries-included attestation server that handles
// challenge generation, validation, and key storage automatically.
//
// This is the recommended way to use the library for most use cases.
// For advanced customization, use NewVerifier directly with your own
// challenge store and key store implementations.
type Server struct {
	verifier   Verifier
	challenges challenge.Store
	keyStore   ios.KeyStore

	mu     sync.RWMutex
	closed bool
}

// ServerConfig holds configuration for the attestation server.
type ServerConfig struct {
	// iOS configuration (optional - omit to disable iOS support)
	IOS *IOSConfig

	// Android configuration (optional - omit to disable Android support)
	Android *AndroidConfig

	// ChallengeTimeout is how long challenges remain valid (default: 5 minutes).
	ChallengeTimeout time.Duration
}

// IOSConfig holds iOS-specific configuration.
type IOSConfig struct {
	// BundleIDs is the list of allowed app bundle identifiers (required).
	BundleIDs []string

	// TeamID is your Apple Developer Team ID (required).
	TeamID string
}

// AndroidConfig holds Android-specific configuration.
type AndroidConfig struct {
	// PackageNames is the list of allowed app package names (required).
	PackageNames []string

	// GCPProjectID is your Google Cloud project ID (required).
	GCPProjectID string

	// GCPCredentialsFile is the path to service account credentials (optional).
	// If empty, uses Application Default Credentials.
	GCPCredentialsFile string

	// APKCertDigests is the list of allowed APK signing certificate SHA-256 digests (optional).
	APKCertDigests []string

	// RequireStrongIntegrity requires hardware-backed attestation (default: false).
	RequireStrongIntegrity bool
}

// NewServer creates a new attestation server with sensible defaults.
//
// Example:
//
//	server, err := attestation.NewServer(attestation.ServerConfig{
//	    IOS: &attestation.IOSConfig{
//	        BundleIDs: []string{"com.example.app"},
//	        TeamID:    "ABCD123456",
//	    },
//	    Android: &attestation.AndroidConfig{
//	        PackageNames: []string{"com.example.app"},
//	        GCPProjectID: "my-project",
//	    },
//	})
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.IOS == nil && cfg.Android == nil {
		return nil, errors.New("at least one platform (iOS or Android) must be configured")
	}

	timeout := cfg.ChallengeTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	// Create internal stores
	challenges := challenge.NewMemoryStore(challenge.Config{
		Timeout: timeout,
	})
	keyStore := ios.NewMemoryKeyStore()

	// Build verifier config
	verifierCfg := Config{
		ChallengeTimeout: timeout,
		KeyStore:         keyStore,
	}

	if cfg.IOS != nil {
		if len(cfg.IOS.BundleIDs) == 0 {
			return nil, errors.New("iOS: at least one bundle ID is required")
		}
		if cfg.IOS.TeamID == "" {
			return nil, errors.New("iOS: team ID is required")
		}
		verifierCfg.IOSBundleIDs = cfg.IOS.BundleIDs
		verifierCfg.IOSTeamID = cfg.IOS.TeamID
	}

	if cfg.Android != nil {
		if len(cfg.Android.PackageNames) == 0 {
			return nil, errors.New("Android: at least one package name is required")
		}
		if cfg.Android.GCPProjectID == "" {
			return nil, errors.New("Android: GCP project ID is required")
		}
		verifierCfg.AndroidPackageNames = cfg.Android.PackageNames
		verifierCfg.GCPProjectID = cfg.Android.GCPProjectID
		verifierCfg.GCPCredentialsFile = cfg.Android.GCPCredentialsFile
		verifierCfg.AndroidAPKCertDigests = cfg.Android.APKCertDigests
		verifierCfg.RequireStrongIntegrity = cfg.Android.RequireStrongIntegrity
	}

	verifier, err := NewVerifier(verifierCfg)
	if err != nil {
		challenges.Close()
		return nil, err
	}

	return &Server{
		verifier:   verifier,
		challenges: challenges,
		keyStore:   keyStore,
	}, nil
}

// GenerateChallenge creates a new challenge for the given identifier.
// The identifier should be unique per attestation flow (e.g., user ID, session ID).
//
// Returns the challenge string that should be sent to the client.
func (s *Server) GenerateChallenge(identifier string) (string, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return "", errors.New("server is closed")
	}
	s.mu.RUnlock()

	return s.challenges.Generate(identifier)
}

// VerifyAttestation verifies a device attestation.
//
// The identifier must match the one used in GenerateChallenge.
// On success, the challenge is consumed and cannot be reused.
//
// Example:
//
//	result, err := server.VerifyAttestation(ctx, "user-123", attestation.VerifyRequest{
//	    Platform:    attestation.PlatformIOS,
//	    Attestation: attestationFromClient,
//	    Challenge:   challengeFromClient,
//	    KeyID:       keyIDFromClient,
//	    BundleID:    "com.example.app",
//	})
func (s *Server) VerifyAttestation(ctx context.Context, identifier string, req VerifyRequest) (*Result, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, errors.New("server is closed")
	}
	s.mu.RUnlock()

	// Validate challenge first
	if !s.challenges.Validate(identifier, req.Challenge) {
		return nil, ErrInvalidChallenge
	}

	// Verify attestation
	return s.verifier.Verify(ctx, &Request{
		Platform:    req.Platform,
		Attestation: req.Attestation,
		Challenge:   req.Challenge,
		KeyID:       req.KeyID,
		BundleID:    req.BundleID,
	})
}

// VerifyRequest contains the attestation data from the client.
type VerifyRequest struct {
	// Platform is the device platform (PlatformIOS or PlatformAndroid).
	Platform Platform

	// Attestation is the base64-encoded attestation data from the device.
	Attestation string

	// Challenge is the challenge that was sent to the client.
	Challenge string

	// KeyID is the key identifier (iOS only).
	KeyID string

	// BundleID is the app bundle identifier (iOS only).
	BundleID string
}

// VerifyAssertion verifies an iOS assertion for subsequent requests.
//
// This requires a previous successful attestation for the given KeyID.
// The assertion counter is automatically tracked to prevent replay attacks.
func (s *Server) VerifyAssertion(ctx context.Context, req AssertionRequest) (*Result, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, errors.New("server is closed")
	}
	s.mu.RUnlock()

	return s.verifier.VerifyAssertion(ctx, &ios.AssertionRequest{
		Assertion:  req.Assertion,
		ClientData: req.ClientData,
		KeyID:      req.KeyID,
		BundleID:   req.BundleID,
	})
}

// AssertionRequest contains the assertion data from the client.
type AssertionRequest struct {
	// Assertion is the base64-encoded assertion from the device.
	Assertion string

	// ClientData is the request-specific data that was signed.
	ClientData []byte

	// KeyID is the key identifier from the original attestation.
	KeyID string

	// BundleID is the app bundle identifier.
	BundleID string
}

// Close releases resources used by the server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	s.challenges.Close()
	return nil
}

// Challenges returns the underlying challenge store for advanced use cases.
func (s *Server) Challenges() challenge.Store {
	return s.challenges
}

// KeyStore returns the underlying key store for advanced use cases.
func (s *Server) KeyStore() ios.KeyStore {
	return s.keyStore
}

// Verifier returns the underlying verifier for advanced use cases.
func (s *Server) Verifier() Verifier {
	return s.verifier
}
