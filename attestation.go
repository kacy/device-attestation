// Package attestation provides device attestation verification for iOS App Attest
// and Android Play Integrity.
//
// This library allows server-side verification of device authenticity to ensure
// requests are coming from legitimate, unmodified apps running on genuine devices.
//
// # iOS App Attest
//
// Verifies attestations and assertions from Apple's App Attest service.
// See: https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity
//
// # Android Play Integrity
//
// Verifies integrity tokens from Google's Play Integrity API.
// See: https://developer.android.com/google/play/integrity
//
// # Basic Usage
//
//	verifier, err := attestation.NewVerifier(attestation.Config{
//	    IOSBundleIDs: []string{"com.example.app"},
//	    IOSTeamID:    "TEAM123456",
//	    AndroidPackageNames: []string{"com.example.app"},
//	    GCPProjectID: "my-project",
//	})
//
//	result, err := verifier.Verify(ctx, &attestation.Request{
//	    Platform:    attestation.PlatformIOS,
//	    Attestation: attestationData,
//	    Challenge:   challenge,
//	    KeyID:       keyID,
//	    BundleID:    "com.example.app",
//	})
package attestation

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kacy/device-attestation/android"
	"github.com/kacy/device-attestation/ios"
)

// Platform represents the mobile platform.
type Platform string

// Platform constants for iOS and Android.
const (
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
)

// Common errors returned by the attestation package.
var (
	ErrInvalidAttestation  = errors.New("invalid attestation")
	ErrAttestationExpired  = errors.New("attestation expired")
	ErrUnsupportedPlatform = errors.New("unsupported platform")
	ErrVerificationFailed  = errors.New("attestation verification failed")
	ErrMissingAttestation  = errors.New("missing attestation data")
	ErrInvalidBundleID     = errors.New("invalid bundle ID")
	ErrInvalidKeyID        = errors.New("invalid key ID")
	ErrInvalidChallenge    = errors.New("invalid challenge")
	ErrInvalidPackageName  = errors.New("invalid package name")
	ErrDeviceCompromised   = errors.New("device integrity check failed")
	ErrAppNotRecognized    = errors.New("app not recognized")
	ErrNotConfigured       = errors.New("platform not configured")
)

// Request represents an attestation or assertion verification request.
type Request struct {
	// Platform is the mobile platform (ios or android).
	Platform Platform

	// Attestation is the base64-encoded attestation data.
	// For iOS: the attestation object from DCAppAttestService.attestKey
	// For Android: the integrity token from Play Integrity API
	Attestation string

	// Challenge is the server-generated challenge that was signed.
	Challenge string

	// KeyID is the key identifier (iOS only).
	// This is the key ID returned by DCAppAttestService.generateKey
	KeyID string

	// BundleID is the app bundle identifier (iOS only).
	BundleID string
}

// Result represents the result of attestation verification.
type Result struct {
	// Valid indicates whether the attestation was successfully verified.
	Valid bool

	// DeviceID is a unique identifier for the device/key.
	// For iOS: the key ID
	// For Android: derived from the nonce
	DeviceID string

	// Platform is the verified platform.
	Platform Platform

	// Timestamp is when the verification was performed.
	Timestamp time.Time
}

// Config holds configuration for the attestation verifier.
type Config struct {
	// iOS App Attest configuration
	IOSBundleIDs []string
	IOSTeamID    string

	// Android Play Integrity configuration
	AndroidPackageNames   []string
	AndroidAPKCertDigests []string
	GCPProjectID          string
	GCPCredentialsFile    string

	// Shared configuration
	ChallengeTimeout time.Duration
	HTTPClient       *http.Client

	// Device integrity requirements
	// When true, Android requires MEETS_STRONG_INTEGRITY verdict
	RequireStrongIntegrity bool

	// KeyStore for storing iOS attestation public keys (optional).
	// Required for assertion verification.
	KeyStore ios.KeyStore
}

// Verifier verifies device attestations.
type Verifier interface {
	// Verify verifies an attestation request.
	Verify(ctx context.Context, req *Request) (*Result, error)

	// VerifyAssertion verifies an iOS assertion (requires KeyStore).
	VerifyAssertion(ctx context.Context, req *ios.AssertionRequest) (*Result, error)
}

type verifier struct {
	config          Config
	iosVerifier     *ios.Verifier
	androidVerifier *android.Verifier
}

// NewVerifier creates a new attestation verifier.
func NewVerifier(cfg Config) (Verifier, error) {
	if cfg.ChallengeTimeout == 0 {
		cfg.ChallengeTimeout = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}

	v := &verifier{config: cfg}

	if len(cfg.IOSBundleIDs) > 0 {
		iosVerifier, err := ios.NewVerifier(ios.Config{
			BundleIDs:        cfg.IOSBundleIDs,
			TeamID:           cfg.IOSTeamID,
			ChallengeTimeout: cfg.ChallengeTimeout,
			KeyStore:         cfg.KeyStore,
		})
		if err != nil {
			return nil, err
		}
		v.iosVerifier = iosVerifier
	}

	if len(cfg.AndroidPackageNames) > 0 {
		androidVerifier, err := android.NewVerifier(android.Config{
			PackageNames:           cfg.AndroidPackageNames,
			APKCertDigests:         cfg.AndroidAPKCertDigests,
			GCPProjectID:           cfg.GCPProjectID,
			GCPCredentialsFile:     cfg.GCPCredentialsFile,
			ChallengeTimeout:       cfg.ChallengeTimeout,
			RequireStrongIntegrity: cfg.RequireStrongIntegrity,
		})
		if err != nil {
			return nil, err
		}
		v.androidVerifier = androidVerifier
	}

	return v, nil
}

// Verify verifies an attestation request.
func (v *verifier) Verify(ctx context.Context, req *Request) (*Result, error) {
	if req == nil || req.Attestation == "" {
		return nil, ErrMissingAttestation
	}

	switch req.Platform {
	case PlatformIOS:
		if v.iosVerifier == nil {
			return nil, ErrNotConfigured
		}
		iosReq := &ios.AttestationRequest{
			Attestation: req.Attestation,
			Challenge:   req.Challenge,
			KeyID:       req.KeyID,
			BundleID:    req.BundleID,
		}
		iosResult, err := v.iosVerifier.VerifyAttestation(ctx, iosReq)
		if err != nil {
			return nil, err
		}
		return &Result{
			Valid:     iosResult.Valid,
			DeviceID:  iosResult.KeyID,
			Platform:  PlatformIOS,
			Timestamp: iosResult.Timestamp,
		}, nil

	case PlatformAndroid:
		if v.androidVerifier == nil {
			return nil, ErrNotConfigured
		}
		androidReq := &android.Request{
			IntegrityToken: req.Attestation,
			Challenge:      req.Challenge,
		}
		androidResult, err := v.androidVerifier.Verify(ctx, androidReq)
		if err != nil {
			return nil, err
		}
		return &Result{
			Valid:     androidResult.Valid,
			DeviceID:  androidResult.DeviceID,
			Platform:  PlatformAndroid,
			Timestamp: androidResult.Timestamp,
		}, nil

	default:
		return nil, ErrUnsupportedPlatform
	}
}

// VerifyAssertion verifies an iOS assertion.
func (v *verifier) VerifyAssertion(ctx context.Context, req *ios.AssertionRequest) (*Result, error) {
	if v.iosVerifier == nil {
		return nil, ErrNotConfigured
	}

	iosResult, err := v.iosVerifier.VerifyAssertion(ctx, req)
	if err != nil {
		return nil, err
	}

	return &Result{
		Valid:     iosResult.Valid,
		DeviceID:  iosResult.KeyID,
		Platform:  PlatformIOS,
		Timestamp: iosResult.Timestamp,
	}, nil
}
