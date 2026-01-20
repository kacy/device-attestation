// Package ios provides iOS App Attest verification.
//
// This package implements Apple's App Attest verification flow for both
// attestation (initial key registration) and assertion (ongoing request signing).
//
// See: https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity
package ios

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Config holds configuration for iOS App Attest verification.
type Config struct {
	// BundleIDs is the list of allowed app bundle identifiers.
	BundleIDs []string

	// TeamID is your Apple Developer Team ID.
	TeamID string

	// ChallengeTimeout is the maximum age of a challenge (default: 5 minutes).
	ChallengeTimeout time.Duration

	// KeyStore for storing attestation public keys.
	// Required for assertion verification.
	KeyStore KeyStore

	// Production indicates whether to use production or development environment.
	// Default is true (production).
	Production bool

	// SkipCertificateVerification skips the certificate chain verification.
	// WARNING: Only use this for development/testing. Never in production!
	SkipCertificateVerification bool
}

// Verifier verifies iOS App Attest attestations and assertions.
type Verifier struct {
	bundleIDSet                 map[string]struct{}
	teamID                      string
	rootCertPool                *x509.CertPool
	timeout                     time.Duration
	keyStore                    KeyStore
	production                  bool
	skipCertificateVerification bool
}

// AttestationRequest represents an attestation verification request.
type AttestationRequest struct {
	// Attestation is the base64-encoded attestation object.
	Attestation string

	// Challenge is the server-generated challenge.
	Challenge string

	// KeyID is the key identifier from DCAppAttestService.generateKey.
	KeyID string

	// BundleID is the app bundle identifier.
	BundleID string
}

// AttestationResult represents the result of attestation verification.
type AttestationResult struct {
	// Valid indicates whether the attestation was verified successfully.
	Valid bool

	// KeyID is the verified key identifier.
	KeyID string

	// PublicKey is the attested public key (for storage).
	PublicKey *ecdsa.PublicKey

	// Receipt is the attestation receipt (for fraud assessment).
	Receipt []byte

	// Timestamp is when the verification was performed.
	Timestamp time.Time
}

// AssertionRequest represents an assertion verification request.
type AssertionRequest struct {
	// Assertion is the base64-encoded assertion object.
	Assertion string

	// ClientData is the client data that was signed.
	ClientData []byte

	// KeyID is the key identifier.
	KeyID string

	// BundleID is the app bundle identifier.
	BundleID string
}

// AssertionResult represents the result of assertion verification.
type AssertionResult struct {
	// Valid indicates whether the assertion was verified successfully.
	Valid bool

	// KeyID is the verified key identifier.
	KeyID string

	// Counter is the new assertion counter value.
	Counter uint32

	// Timestamp is when the verification was performed.
	Timestamp time.Time
}

// Common errors.
var (
	ErrInvalidAttestation = errors.New("invalid attestation")
	ErrInvalidAssertion   = errors.New("invalid assertion")
	ErrVerificationFailed = errors.New("verification failed")
	ErrInvalidBundleID    = errors.New("invalid bundle ID")
	ErrInvalidKeyID       = errors.New("invalid key ID")
	ErrInvalidChallenge   = errors.New("invalid challenge")
	ErrCounterReplay      = errors.New("assertion counter replay detected")
	ErrKeyStoreRequired   = errors.New("key store required for assertion verification")
)

// NewVerifier creates a new iOS App Attest verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	if len(cfg.BundleIDs) == 0 {
		return nil, errors.New("at least one bundle ID is required")
	}
	if cfg.TeamID == "" {
		return nil, errors.New("team ID is required")
	}

	bundleIDSet := make(map[string]struct{}, len(cfg.BundleIDs))
	for _, id := range cfg.BundleIDs {
		bundleIDSet[id] = struct{}{}
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(appleAppAttestRootCA)) {
		return nil, errors.New("failed to parse Apple root CA")
	}
	// Also add the development root CA for testing environments
	pool.AppendCertsFromPEM([]byte(appleAppAttestDevRootCA))

	timeout := cfg.ChallengeTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	production := cfg.Production
	if !cfg.Production && cfg.TeamID != "" {
		production = true // Default to production
	}

	return &Verifier{
		bundleIDSet:                 bundleIDSet,
		teamID:                      cfg.TeamID,
		rootCertPool:                pool,
		timeout:                     timeout,
		keyStore:                    cfg.KeyStore,
		production:                  production,
		skipCertificateVerification: cfg.SkipCertificateVerification,
	}, nil
}

// VerifyAttestation verifies an iOS App Attest attestation.
func (v *Verifier) VerifyAttestation(ctx context.Context, req *AttestationRequest) (*AttestationResult, error) {
	if _, ok := v.bundleIDSet[req.BundleID]; !ok {
		return nil, fmt.Errorf("%w: bundle_id=%s not in allowed set", ErrInvalidBundleID, req.BundleID)
	}

	if req.KeyID == "" {
		return nil, fmt.Errorf("%w: key_id is empty", ErrInvalidKeyID)
	}

	attestationData, err := base64.StdEncoding.DecodeString(req.Attestation)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode attestation base64: %v", ErrInvalidAttestation, err)
	}

	attestObj, err := v.parseAttestationObject(attestationData)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse attestation object: %v", ErrInvalidAttestation, err)
	}

	certs, err := v.parseCertificateChain(attestObj.AttStatement.X5c)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse certificate chain: %v", ErrInvalidAttestation, err)
	}

	if err := v.verifyCertificateChain(certs); err != nil {
		return nil, fmt.Errorf("%w: certificate chain verification failed: %v", ErrVerificationFailed, err)
	}

	if err := v.verifyAuthenticatorData(attestObj.AuthData, req.BundleID); err != nil {
		return nil, fmt.Errorf("%w: authenticator data verification failed: %v", ErrVerificationFailed, err)
	}

	clientDataHash := sha256.Sum256([]byte(req.Challenge))
	if err := v.verifyNonce(certs[0], attestObj.AuthData, clientDataHash[:]); err != nil {
		return nil, fmt.Errorf("%w: nonce verification failed: %v", ErrVerificationFailed, err)
	}

	publicKey, err := v.extractPublicKey(certs[0])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to extract public key: %v", ErrVerificationFailed, err)
	}

	if err := v.verifyKeyID(publicKey, req.KeyID); err != nil {
		return nil, fmt.Errorf("%w: key ID verification failed: %v", ErrVerificationFailed, err)
	}

	// Store the public key if a key store is configured
	if v.keyStore != nil {
		storedKey := &StoredKey{
			KeyID:     req.KeyID,
			PublicKey: publicKey,
			BundleID:  req.BundleID,
			TeamID:    v.teamID,
			Counter:   0,
		}
		if err := v.keyStore.Store(ctx, req.KeyID, storedKey); err != nil && !errors.Is(err, ErrKeyExists) {
			return nil, fmt.Errorf("failed to store public key: %w", err)
		}
	}

	return &AttestationResult{
		Valid:     true,
		KeyID:     req.KeyID,
		PublicKey: publicKey,
		Receipt:   attestObj.AttStatement.Receipt,
		Timestamp: time.Now(),
	}, nil
}

// VerifyAssertion verifies an iOS App Attest assertion.
func (v *Verifier) VerifyAssertion(ctx context.Context, req *AssertionRequest) (*AssertionResult, error) {
	if v.keyStore == nil {
		return nil, ErrKeyStoreRequired
	}

	if _, ok := v.bundleIDSet[req.BundleID]; !ok {
		return nil, ErrInvalidBundleID
	}

	if req.KeyID == "" {
		return nil, ErrInvalidKeyID
	}

	// Load the stored key
	storedKey, err := v.keyStore.Load(ctx, req.KeyID)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	// Verify bundle ID matches
	if storedKey.BundleID != req.BundleID {
		return nil, ErrInvalidBundleID
	}

	// Decode assertion
	assertionData, err := base64.StdEncoding.DecodeString(req.Assertion)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode assertion: %v", ErrInvalidAssertion, err)
	}

	// Parse assertion object
	assertObj, err := v.parseAssertionObject(assertionData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAssertion, err)
	}

	// Verify authenticator data
	if err := v.verifyAssertionAuthData(assertObj.AuthenticatorData, req.BundleID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	// Extract and verify counter
	counter := v.extractCounter(assertObj.AuthenticatorData)
	if counter <= storedKey.Counter {
		return nil, ErrCounterReplay
	}

	// Compute client data hash
	clientDataHash := sha256.Sum256(req.ClientData)

	// Compute nonce (authenticatorData || clientDataHash)
	nonceData := make([]byte, len(assertObj.AuthenticatorData)+len(clientDataHash))
	copy(nonceData, assertObj.AuthenticatorData)
	copy(nonceData[len(assertObj.AuthenticatorData):], clientDataHash[:])
	nonce := sha256.Sum256(nonceData)

	// Verify signature
	if !ecdsa.VerifyASN1(storedKey.PublicKey, nonce[:], assertObj.Signature) {
		return nil, fmt.Errorf("%w: signature verification failed", ErrVerificationFailed)
	}

	// Update counter
	newCounter, err := v.keyStore.IncrementCounter(ctx, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to update counter: %w", err)
	}

	return &AssertionResult{
		Valid:     true,
		KeyID:     req.KeyID,
		Counter:   newCounter,
		Timestamp: time.Now(),
	}, nil
}

// attestationObject represents the CBOR-encoded attestation object.
type attestationObject struct {
	Format       string       `cbor:"fmt"`
	AttStatement attStatement `cbor:"attStmt"`
	AuthData     []byte       `cbor:"authData"`
}

type attStatement struct {
	X5c     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt,omitempty"`
}

// assertionObject represents the CBOR-encoded assertion object.
type assertionObject struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

func (v *Verifier) parseAttestationObject(data []byte) (*attestationObject, error) {
	var obj attestationObject
	if err := cbor.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("failed to decode CBOR attestation object: %w", err)
	}

	if obj.Format != "apple-appattest" {
		return nil, fmt.Errorf("unexpected attestation format: %s", obj.Format)
	}

	if len(obj.AttStatement.X5c) < 2 {
		return nil, errors.New("certificate chain too short")
	}

	if len(obj.AuthData) < 37 {
		return nil, errors.New("authenticator data too short")
	}

	return &obj, nil
}

func (v *Verifier) parseAssertionObject(data []byte) (*assertionObject, error) {
	var obj assertionObject
	if err := cbor.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("failed to decode CBOR assertion object: %w", err)
	}

	if len(obj.Signature) == 0 {
		return nil, errors.New("missing signature")
	}

	if len(obj.AuthenticatorData) < 37 {
		return nil, errors.New("authenticator data too short")
	}

	return &obj, nil
}

func (v *Verifier) parseCertificateChain(x5c [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(x5c))
	for i, certDER := range x5c {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}
		certs[i] = cert
	}
	return certs, nil
}

func (v *Verifier) verifyCertificateChain(certs []*x509.Certificate) error {
	if len(certs) < 2 {
		return errors.New("certificate chain too short")
	}

	// Skip certificate verification if configured (development only!)
	if v.skipCertificateVerification {
		// Still verify the App Attest OID is present for basic security
		credCertOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
		found := false
		for _, ext := range certs[0].Extensions {
			if ext.Id.Equal(credCertOID) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("leaf certificate missing App Attest credential certificate OID")
		}
		return nil
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         v.rootCertPool,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Verify the leaf certificate has the App Attest OID
	credCertOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	found := false
	for _, ext := range certs[0].Extensions {
		if ext.Id.Equal(credCertOID) {
			found = true
			break
		}
	}
	if !found {
		return errors.New("leaf certificate missing App Attest credential certificate OID")
	}

	return nil
}

func (v *Verifier) verifyAuthenticatorData(authData []byte, bundleID string) error {
	appID := v.teamID + "." + bundleID
	expectedRPIDHash := sha256.Sum256([]byte(appID))

	rpIDHash := authData[:32]
	if !bytes.Equal(rpIDHash, expectedRPIDHash[:]) {
		return errors.New("RP ID hash mismatch")
	}

	flags := authData[32]
	if flags&0x40 == 0 {
		return errors.New("attested credential data flag not set")
	}

	return nil
}

func (v *Verifier) verifyAssertionAuthData(authData []byte, bundleID string) error {
	appID := v.teamID + "." + bundleID
	expectedRPIDHash := sha256.Sum256([]byte(appID))

	rpIDHash := authData[:32]
	if !bytes.Equal(rpIDHash, expectedRPIDHash[:]) {
		return errors.New("RP ID hash mismatch")
	}

	flags := authData[32]
	if flags&0x01 == 0 {
		return errors.New("user present flag not set")
	}

	return nil
}

func (v *Verifier) extractCounter(authData []byte) uint32 {
	// Counter is at bytes 33-36 (4 bytes, big-endian)
	return binary.BigEndian.Uint32(authData[33:37])
}

func (v *Verifier) verifyNonce(cert *x509.Certificate, authData, clientDataHash []byte) error {
	composite := make([]byte, len(authData)+len(clientDataHash))
	copy(composite, authData)
	copy(composite[len(authData):], clientDataHash)
	expectedNonce := sha256.Sum256(composite)

	nonceOID := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 1}

	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(nonceOID) {
			continue
		}

		var outerSeq asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &outerSeq)
		if err != nil || len(rest) > 0 {
			return errors.New("failed to parse nonce extension")
		}

		var innerSeq asn1.RawValue
		rest, err = asn1.Unmarshal(outerSeq.Bytes, &innerSeq)
		if err != nil || len(rest) > 0 {
			return errors.New("failed to parse nonce sequence")
		}

		var nonce []byte
		_, err = asn1.Unmarshal(innerSeq.Bytes, &nonce)
		if err != nil {
			nonce = innerSeq.Bytes
		}

		if bytes.Equal(nonce, expectedNonce[:]) {
			return nil
		}

		return errors.New("nonce mismatch")
	}

	return errors.New("nonce extension not found")
}

func (v *Verifier) extractPublicKey(cert *x509.Certificate) (*ecdsa.PublicKey, error) {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate public key is not ECDSA")
	}
	return pubKey, nil
}

func (v *Verifier) verifyKeyID(pubKey *ecdsa.PublicKey, keyID string) error {
	// Try uncompressed format first (0x04 || X || Y)
	pubKeyUncompressed := make([]byte, 65)
	pubKeyUncompressed[0] = 0x04
	pubKey.X.FillBytes(pubKeyUncompressed[1:33])
	pubKey.Y.FillBytes(pubKeyUncompressed[33:65])

	computedHash := sha256.Sum256(pubKeyUncompressed)
	computedKeyID := base64.StdEncoding.EncodeToString(computedHash[:])

	if computedKeyID == keyID {
		return nil
	}

	// Try raw X||Y format
	pubKeyBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	computedHash = sha256.Sum256(pubKeyBytes)
	computedKeyID = base64.StdEncoding.EncodeToString(computedHash[:])

	if computedKeyID == keyID {
		return nil
	}

	return fmt.Errorf("key ID mismatch: computed %s, expected %s", computedKeyID, keyID)
}

// Apple App Attest Root CA certificate (Production)
const appleAppAttestRootCA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDEx1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UEChMK
QXBwbGUgSW5jLjETMBEGA1UECBMKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw0zOTAzMTgwMDAwMDBaMFIxJjAkBgNVBAMTHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKEwpBcHBsZSBJbmMuMRMwEQYDVQQIEwpDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

// Apple App Attest Root CA certificate (Development/Sandbox)
// This is used when testing on development devices or simulators
const appleAppAttestDevRootCA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDEx1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UEChMK
QXBwbGUgSW5jLjETMBEGA1UECBMKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw0zOTAzMTgwMDAwMDBaMFIxJjAkBgNVBAMTHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKEwpBcHBsZSBJbmMuMRMwEQYDVQQIEwpDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`
