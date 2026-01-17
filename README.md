# 📱 device-attestation

A Go library for verifying device attestations from iOS (App Attest) and Android (Play Integrity).

This library allows server-side verification of device authenticity to ensure requests are coming from legitimate, unmodified apps running on genuine devices.

## Features

- **iOS App Attest**: Full attestation and assertion verification
- **Android Play Integrity**: Token verification via Google's official API
- **Challenge Management**: Cryptographically secure challenge generation with expiration
- **Key Storage**: Interface for persisting iOS attestation public keys
- **Replay Protection**: Counter-based assertion replay detection for iOS
- **Configurable Security**: Adjustable integrity requirements for Android

## Installation

```bash
go get github.com/kacy/device-attestation
```

## Quick Start

The simplest way to get started is with the `Server` type, which handles challenge management and key storage automatically:

```go
package main

import (
    "context"
    "log"

    attestation "github.com/kacy/device-attestation"
)

func main() {
    // Create an attestation server (batteries included)
    server, err := attestation.NewServer(attestation.ServerConfig{
        IOS: &attestation.IOSConfig{
            BundleIDs: []string{"com.example.myapp"},
            TeamID:    "ABCD123456",
        },
        Android: &attestation.AndroidConfig{
            PackageNames: []string{"com.example.myapp"},
            GCPProjectID: "my-gcp-project",
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer server.Close()

    // 1. Generate a challenge for the client
    challenge, _ := server.GenerateChallenge("user-123")
    // Send challenge to client...

    // 2. Verify the attestation from the client
    result, err := server.VerifyAttestation(context.Background(), "user-123", attestation.VerifyRequest{
        Platform:    attestation.PlatformIOS,
        Attestation: "<base64-attestation-from-client>",
        Challenge:   challenge,
        KeyID:       "<key-id-from-client>",
        BundleID:    "com.example.myapp",
    })
    if err != nil {
        log.Printf("Attestation failed: %v", err)
        return
    }

    log.Printf("Device verified: %s", result.DeviceID)
}
```

## Advanced Usage

For more control, you can use the lower-level `Verifier` API with custom challenge and key stores:

```go
import (
    attestation "github.com/kacy/device-attestation"
    "github.com/kacy/device-attestation/challenge"
    "github.com/kacy/device-attestation/ios"
)

// Create custom stores
challenges := challenge.NewMemoryStore(challenge.Config{Timeout: 5 * time.Minute})
keyStore := ios.NewMemoryKeyStore()

// Create verifier with full control
verifier, _ := attestation.NewVerifier(attestation.Config{
    IOSBundleIDs:           []string{"com.example.myapp"},
    IOSTeamID:              "ABCD123456",
    AndroidPackageNames:    []string{"com.example.myapp"},
    GCPProjectID:           "my-project",
    KeyStore:               keyStore,
    RequireStrongIntegrity: true,
})

// Manual challenge management
challenge, _ := challenges.Generate("user-123")
// ... send to client ...
if !challenges.Validate("user-123", clientChallenge) {
    // Invalid challenge
}

// Verify with the low-level API
result, err := verifier.Verify(ctx, &attestation.Request{...})
```

## iOS App Attest

### How It Works

1. **Client generates a key pair** using `DCAppAttestService.generateKey()`
2. **Server generates a challenge** and sends it to the client
3. **Client creates attestation** using `DCAppAttestService.attestKey()`
4. **Server verifies attestation** using this library
5. **Server stores the public key** for future assertion verification
6. **Subsequent requests** use assertions signed with the attested key

### Attestation Verification

```go
import "github.com/kacy/device-attestation/ios"

verifier, _ := ios.NewVerifier(ios.Config{
    BundleIDs: []string{"com.example.myapp"},
    TeamID:    "ABCD123456",
    KeyStore:  ios.NewMemoryKeyStore(), // Required for assertion verification
})

result, err := verifier.VerifyAttestation(ctx, &ios.AttestationRequest{
    Attestation: attestationBase64,
    Challenge:   serverChallenge,
    KeyID:       keyID,
    BundleID:    "com.example.myapp",
})
```

### Assertion Verification

After initial attestation, use assertions to verify subsequent requests:

```go
result, err := verifier.VerifyAssertion(ctx, &ios.AssertionRequest{
    Assertion:  assertionBase64,
    ClientData: []byte("request-specific-data"),
    KeyID:      keyID,
    BundleID:   "com.example.myapp",
})
```

The library automatically:
- Retrieves the stored public key
- Verifies the signature
- Checks the counter to prevent replay attacks
- Updates the counter on success

## Android Play Integrity

### Prerequisites

1. Enable the Play Integrity API in Google Cloud Console
2. Link your app in Google Play Console
3. Create a service account with Play Integrity API access

### Verification

```go
import "github.com/kacy/device-attestation/android"

verifier, _ := android.NewVerifier(android.Config{
    PackageNames:       []string{"com.example.myapp"},
    GCPProjectID:       "my-project",
    GCPCredentialsFile: "/path/to/credentials.json", // Optional, uses ADC if empty

    // Optional: APK signing certificate SHA-256 digests
    APKCertDigests: []string{"AA:BB:CC:..."},

    // Security requirements
    RequireStrongIntegrity: false, // Require hardware-backed attestation
    AllowBasicIntegrity:    false, // Allow potentially rooted devices
})

result, err := verifier.Verify(ctx, &android.Request{
    IntegrityToken: tokenFromClient,
    Challenge:      serverChallenge,
})
```

### Device Integrity Levels

| Verdict | Meaning |
|---------|---------|
| `MEETS_STRONG_INTEGRITY` | Genuine device with hardware-backed security |
| `MEETS_DEVICE_INTEGRITY` | Genuine device with Google Play services |
| `MEETS_BASIC_INTEGRITY` | Device may be rooted or running custom ROM |

## Challenge Store

The challenge store generates cryptographically secure challenges and handles expiration:

```go
import "github.com/kacy/device-attestation/challenge"

store := challenge.NewMemoryStore(challenge.Config{
    Timeout:         5 * time.Minute,  // Challenge validity period
    CleanupInterval: 1 * time.Minute,  // Expired challenge cleanup interval
    ChallengeBytes:  32,               // Random bytes in challenge
})
defer store.Close()

// Generate a challenge for a user
ch, _ := store.Generate("user-123")

// Validate (consumes the challenge on success)
valid := store.Validate("user-123", ch)
```

## Redis (Distributed Deployments)

For distributed systems where multiple server instances need to share state, use the Redis-backed stores:

```go
import (
    "github.com/redis/go-redis/v9"
    attestredis "github.com/kacy/device-attestation/redis"
)

// Create your Redis client (you control the connection)
rdb := redis.NewClient(&redis.Options{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
})

// Create Redis-backed challenge store
challenges, _ := attestredis.NewChallengeStore(attestredis.ChallengeStoreConfig{
    Client:    rdb,
    KeyPrefix: "myapp:challenge:",  // Optional, default: "attest:challenge:"
    Timeout:   5 * time.Minute,
})

// Create Redis-backed key store
keyStore, _ := attestredis.NewKeyStore(attestredis.KeyStoreConfig{
    Client:    rdb,
    KeyPrefix: "myapp:key:",  // Optional, default: "attest:key:"
    TTL:       0,             // 0 = no expiration
})

// Use with the advanced API
verifier, _ := attestation.NewVerifier(attestation.Config{
    IOSBundleIDs: []string{"com.example.app"},
    IOSTeamID:    "TEAM123",
    KeyStore:     keyStore,
})
```

The Redis package defines a `Cmdable` interface compatible with `github.com/redis/go-redis/v9`, so you can pass in a `*redis.Client`, `*redis.ClusterClient`, or any compatible client.

## Key Storage (iOS)

The KeyStore is used for iOS **assertion** verification. Here's why it exists:

1. **Attestation** (one-time): Device proves it's genuine, server extracts the public key
2. **Assertion** (ongoing): Device signs requests with its private key, server verifies using the stored public key

The KeyStore persists the public key and tracks a counter to prevent replay attacks.

### When You Don't Need a KeyStore

If you're only using attestation as a one-time device check (e.g., during account registration) and don't need ongoing assertion verification, you can skip the KeyStore:

```go
// Attestation-only mode
server, _ := attestation.NewServer(attestation.ServerConfig{
    IOS: &attestation.IOSConfig{
        BundleIDs: []string{"com.example.app"},
        TeamID:    "TEAM123",
    },
    // No KeyStore configured - attestation works, assertions won't
})
```

### When You Need a KeyStore

If you want to verify assertions on subsequent requests (recommended for ongoing API security):

```go
// Full attestation + assertion support
verifier, _ := attestation.NewVerifier(attestation.Config{
    IOSBundleIDs: []string{"com.example.app"},
    IOSTeamID:    "TEAM123",
    KeyStore:     ios.NewMemoryKeyStore(), // or Redis for distributed
})
```

### KeyStore Interface

```go
type KeyStore interface {
    Store(ctx context.Context, keyID string, key *StoredKey) error
    Load(ctx context.Context, keyID string) (*StoredKey, error)
    Delete(ctx context.Context, keyID string) error
    IncrementCounter(ctx context.Context, keyID string) (uint32, error)
}
```

### In-Memory (Development/Single Instance)

Suitable for development, testing, or single-server deployments:

```go
keyStore := ios.NewMemoryKeyStore()
```

Note: Data is lost on server restart. For production single-instance deployments, consider Redis or a database.

### Redis (Distributed)

For multi-instance deployments where servers need to share state:

```go
keyStore, _ := attestredis.NewKeyStore(attestredis.KeyStoreConfig{
    Client: redisClient,
})
```

### Custom Implementation

You can implement the interface with any backend (PostgreSQL, DynamoDB, etc.):

```go
type MyKeyStore struct {
    // your fields
}

func (s *MyKeyStore) Store(ctx context.Context, keyID string, key *ios.StoredKey) error {
    // your implementation
}
// ... implement other methods
```

## Configuration Reference

### Main Verifier Config

| Field | Type | Description |
|-------|------|-------------|
| `IOSBundleIDs` | `[]string` | Allowed iOS bundle identifiers |
| `IOSTeamID` | `string` | Apple Developer Team ID |
| `AndroidPackageNames` | `[]string` | Allowed Android package names |
| `AndroidAPKCertDigests` | `[]string` | APK signing certificate SHA-256 digests |
| `GCPProjectID` | `string` | Google Cloud project ID |
| `GCPCredentialsFile` | `string` | Path to service account JSON (optional) |
| `ChallengeTimeout` | `time.Duration` | Maximum challenge age (default: 5m) |
| `RequireStrongIntegrity` | `bool` | Require Android strong integrity |
| `KeyStore` | `ios.KeyStore` | Storage for iOS public keys |

## Error Handling

The library returns typed errors for different failure cases:

```go
import attestation "github.com/kacy/device-attestation"

result, err := verifier.Verify(ctx, req)
if err != nil {
    switch {
    case errors.Is(err, attestation.ErrInvalidAttestation):
        // Malformed attestation data
    case errors.Is(err, attestation.ErrVerificationFailed):
        // Cryptographic verification failed
    case errors.Is(err, attestation.ErrInvalidBundleID):
        // Bundle ID not in allowed list
    case errors.Is(err, attestation.ErrDeviceCompromised):
        // Android device integrity check failed
    case errors.Is(err, attestation.ErrAppNotRecognized):
        // App not recognized by Play Store
    default:
        // Other error
    }
}
```

## Security Considerations

1. **Always use HTTPS** for transmitting attestation data
2. **Generate unique challenges** per attestation request
3. **Set appropriate timeouts** for challenges (recommended: 1-5 minutes)
4. **Store iOS public keys securely** with proper access controls
5. **Monitor attestation failures** for potential abuse patterns
6. **Consider rate limiting** attestation endpoints

## Client-Side Implementation

### iOS (Swift)

```swift
import DeviceCheck

let service = DCAppAttestService.shared

// Generate key
service.generateKey { keyId, error in
    guard let keyId = keyId else { return }
    
    // Get challenge from server, then attest
    let challenge = Data(challengeString.utf8)
    let hash = SHA256.hash(data: challenge)
    
    service.attestKey(keyId, clientDataHash: Data(hash)) { attestation, error in
        // Send attestation to server
    }
}
```

### Android (Kotlin)

```kotlin
val integrityManager = IntegrityManagerFactory.create(context)

val request = IntegrityTokenRequest.builder()
    .setNonce(challengeFromServer)
    .build()

integrityManager.requestIntegrityToken(request)
    .addOnSuccessListener { response ->
        val token = response.token()
        // Send token to server
    }
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
