// Package android provides Android Play Integrity verification.
//
// This package uses Google's official Play Integrity API to verify
// integrity tokens from Android devices.
//
// See: https://developer.android.com/google/play/integrity
package android

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/option"
	"google.golang.org/api/playintegrity/v1"
)

// Config holds configuration for Android Play Integrity verification.
type Config struct {
	// PackageNames is the list of allowed app package names.
	PackageNames []string

	// APKCertDigests is the list of allowed APK signing certificate SHA-256 digests.
	// Optional but recommended for additional security.
	APKCertDigests []string

	// GCPProjectID is your Google Cloud project ID.
	GCPProjectID string

	// GCPCredentialsFile is the path to the service account credentials file.
	// If empty, uses Application Default Credentials.
	GCPCredentialsFile string

	// ChallengeTimeout is the maximum age of a token (default: 5 minutes).
	ChallengeTimeout time.Duration

	// RequireStrongIntegrity requires MEETS_STRONG_INTEGRITY verdict.
	// When false, MEETS_DEVICE_INTEGRITY is sufficient.
	RequireStrongIntegrity bool

	// AllowBasicIntegrity allows MEETS_BASIC_INTEGRITY verdict.
	// Not recommended for sensitive operations.
	AllowBasicIntegrity bool
}

// Verifier verifies Android Play Integrity tokens.
type Verifier struct {
	service        *playintegrity.Service
	packageNameSet map[string]struct{}
	certDigestSet  map[string]struct{}
	packageName    string
	timeout        time.Duration
	requireStrong  bool
	allowBasic     bool
}

// Request represents an integrity verification request.
type Request struct {
	// IntegrityToken is the token from the Play Integrity API.
	IntegrityToken string

	// Challenge is the server-generated nonce.
	Challenge string
}

// Result represents the result of integrity verification.
type Result struct {
	// Valid indicates whether the integrity token was verified successfully.
	Valid bool

	// DeviceID is derived from the request nonce.
	DeviceID string

	// PackageName is the verified package name.
	PackageName string

	// AppRecognitionVerdict is the app recognition result.
	AppRecognitionVerdict string

	// DeviceIntegrityVerdicts contains the device integrity verdicts.
	DeviceIntegrityVerdicts []string

	// AccountDetails contains the licensing information (if available).
	AccountDetails *AccountDetails

	// Timestamp is when the verification was performed.
	Timestamp time.Time
}

// AccountDetails contains Play Store licensing information.
type AccountDetails struct {
	// LicensingVerdict indicates the app licensing status.
	// Values: LICENSED, UNLICENSED, UNEVALUATED
	LicensingVerdict string
}

// Common errors.
var (
	ErrVerificationFailed = errors.New("verification failed")
	ErrInvalidPackageName = errors.New("invalid package name")
	ErrInvalidChallenge   = errors.New("invalid challenge")
	ErrAttestationExpired = errors.New("attestation expired")
	ErrDeviceCompromised  = errors.New("device integrity check failed")
	ErrAppNotRecognized   = errors.New("app not recognized")
	ErrCertDigestMismatch = errors.New("APK certificate digest mismatch")
)

// NewVerifier creates a new Android Play Integrity verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	if len(cfg.PackageNames) == 0 {
		return nil, errors.New("at least one package name is required")
	}
	if cfg.GCPProjectID == "" {
		return nil, errors.New("GCP project ID is required")
	}

	ctx := context.Background()

	var opts []option.ClientOption
	if cfg.GCPCredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.GCPCredentialsFile))
	}

	service, err := playintegrity.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Play Integrity service: %w", err)
	}

	packageNameSet := make(map[string]struct{}, len(cfg.PackageNames))
	for _, name := range cfg.PackageNames {
		packageNameSet[name] = struct{}{}
	}

	certDigestSet := make(map[string]struct{}, len(cfg.APKCertDigests))
	for _, digest := range cfg.APKCertDigests {
		certDigestSet[strings.ToUpper(digest)] = struct{}{}
	}

	timeout := cfg.ChallengeTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	return &Verifier{
		service:        service,
		packageNameSet: packageNameSet,
		certDigestSet:  certDigestSet,
		packageName:    cfg.PackageNames[0],
		timeout:        timeout,
		requireStrong:  cfg.RequireStrongIntegrity,
		allowBasic:     cfg.AllowBasicIntegrity,
	}, nil
}

// Verify verifies an Android Play Integrity token.
func (v *Verifier) Verify(ctx context.Context, req *Request) (*Result, error) {
	decodeReq := &playintegrity.DecodeIntegrityTokenRequest{
		IntegrityToken: req.IntegrityToken,
	}

	call := v.service.V1.DecodeIntegrityToken(v.packageName, decodeReq)
	resp, err := call.Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode integrity token: %v", ErrVerificationFailed, err)
	}

	payload := resp.TokenPayloadExternal
	if payload == nil {
		return nil, fmt.Errorf("%w: empty token payload", ErrVerificationFailed)
	}

	if err := v.verifyRequestDetails(payload.RequestDetails, req.Challenge); err != nil {
		return nil, err
	}

	if err := v.verifyAppIntegrity(payload.AppIntegrity); err != nil {
		return nil, err
	}

	if err := v.verifyDeviceIntegrity(payload.DeviceIntegrity); err != nil {
		return nil, err
	}

	result := &Result{
		Valid:                   true,
		DeviceID:                payload.RequestDetails.Nonce,
		PackageName:             payload.AppIntegrity.PackageName,
		AppRecognitionVerdict:   payload.AppIntegrity.AppRecognitionVerdict,
		DeviceIntegrityVerdicts: payload.DeviceIntegrity.DeviceRecognitionVerdict,
		Timestamp:               time.Now(),
	}

	// Include account details if available
	if payload.AccountDetails != nil {
		result.AccountDetails = &AccountDetails{
			LicensingVerdict: payload.AccountDetails.AppLicensingVerdict,
		}
	}

	return result, nil
}

func (v *Verifier) verifyRequestDetails(details *playintegrity.RequestDetails, expectedChallenge string) error {
	if details == nil {
		return fmt.Errorf("%w: missing request details", ErrVerificationFailed)
	}

	// Verify nonce matches challenge
	nonce := details.Nonce
	decodedNonce, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		decodedNonce = []byte(nonce)
	}

	if string(decodedNonce) != expectedChallenge && nonce != expectedChallenge {
		return ErrInvalidChallenge
	}

	// Verify package name
	packageName := details.RequestPackageName
	if _, ok := v.packageNameSet[packageName]; !ok {
		return fmt.Errorf("%w: unexpected package name: %s", ErrInvalidPackageName, packageName)
	}

	// Verify timestamp
	timestampMillis := details.TimestampMillis
	requestTime := time.UnixMilli(timestampMillis)
	age := time.Since(requestTime)

	if age > v.timeout {
		return fmt.Errorf("%w: token too old (%v)", ErrAttestationExpired, age)
	}
	if age < -1*time.Minute {
		return fmt.Errorf("%w: token from the future", ErrAttestationExpired)
	}

	return nil
}

func (v *Verifier) verifyAppIntegrity(appIntegrity *playintegrity.AppIntegrity) error {
	if appIntegrity == nil {
		return fmt.Errorf("%w: missing app integrity", ErrVerificationFailed)
	}

	verdict := appIntegrity.AppRecognitionVerdict
	switch verdict {
	case "PLAY_RECOGNIZED":
		// App binary matches what's on Play Store - good
	case "UNRECOGNIZED_VERSION":
		return fmt.Errorf("%w: app version not recognized by Play Store", ErrAppNotRecognized)
	case "UNEVALUATED":
		return fmt.Errorf("%w: app integrity not evaluated", ErrAppNotRecognized)
	default:
		return fmt.Errorf("%w: unknown app recognition verdict: %s", ErrAppNotRecognized, verdict)
	}

	// Verify package name in app integrity
	packageName := appIntegrity.PackageName
	if _, ok := v.packageNameSet[packageName]; !ok {
		return fmt.Errorf("%w: package name mismatch in app integrity", ErrInvalidPackageName)
	}

	// Verify APK certificate digests if configured
	if len(v.certDigestSet) > 0 {
		certDigests := appIntegrity.CertificateSha256Digest
		found := false
		for _, digest := range certDigests {
			if _, ok := v.certDigestSet[strings.ToUpper(digest)]; ok {
				found = true
				break
			}
		}
		if !found {
			return ErrCertDigestMismatch
		}
	}

	return nil
}

func (v *Verifier) verifyDeviceIntegrity(deviceIntegrity *playintegrity.DeviceIntegrity) error {
	if deviceIntegrity == nil {
		return fmt.Errorf("%w: missing device integrity", ErrVerificationFailed)
	}

	verdicts := deviceIntegrity.DeviceRecognitionVerdict

	hasBasic := false
	hasDevice := false
	hasStrong := false

	for _, verdict := range verdicts {
		switch verdict {
		case "MEETS_BASIC_INTEGRITY":
			hasBasic = true
		case "MEETS_DEVICE_INTEGRITY":
			hasDevice = true
		case "MEETS_STRONG_INTEGRITY":
			hasStrong = true
		}
	}

	if v.requireStrong {
		if !hasStrong {
			return fmt.Errorf("%w: device does not meet strong integrity requirements (verdicts: %v)", ErrDeviceCompromised, verdicts)
		}
		return nil
	}

	if hasDevice || hasStrong {
		return nil
	}

	if hasBasic && v.allowBasic {
		return nil
	}

	if hasBasic {
		return fmt.Errorf("%w: device only meets basic integrity (may be rooted/modified)", ErrDeviceCompromised)
	}

	return fmt.Errorf("%w: device integrity check failed (verdicts: %v)", ErrDeviceCompromised, verdicts)
}
