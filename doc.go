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
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	result, err := verifier.Verify(ctx, &attestation.Request{
//	    Platform:    attestation.PlatformIOS,
//	    Attestation: attestationData,
//	    Challenge:   challenge,
//	    KeyID:       keyID,
//	    BundleID:    "com.example.app",
//	})
//
// # Subpackages
//
// The library is organized into the following subpackages:
//
//   - ios: iOS App Attest verification (attestation and assertion)
//   - android: Android Play Integrity verification
//   - challenge: Secure challenge generation and validation
//
// For more details, see the README at https://github.com/kacy/device-attestation
package attestation
