// Example: Basic device attestation verification server
//
// This example demonstrates how to set up a simple HTTP server
// that verifies device attestations from iOS and Android clients.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	attestation "github.com/kacy/device-attestation"
)

// ChallengeResponse is returned when requesting a new challenge.
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
}

// AttestRequest is the request body for attestation verification.
type AttestRequest struct {
	Platform    string `json:"platform"`
	Attestation string `json:"attestation"`
	Challenge   string `json:"challenge"`
	KeyID       string `json:"key_id,omitempty"`
	BundleID    string `json:"bundle_id,omitempty"`
}

// AttestResponse is returned after successful attestation.
type AttestResponse struct {
	Valid    bool   `json:"valid"`
	DeviceID string `json:"device_id"`
	Platform string `json:"platform"`
}

func main() {
	// Create attestation server with the simple API
	server, err := attestation.NewServer(attestation.ServerConfig{
		// iOS configuration
		IOS: &attestation.IOSConfig{
			BundleIDs: []string{os.Getenv("IOS_BUNDLE_ID")},
			TeamID:    os.Getenv("IOS_TEAM_ID"),
		},
		// Android configuration (optional - comment out if not needed)
		Android: &attestation.AndroidConfig{
			PackageNames: []string{os.Getenv("ANDROID_PACKAGE_NAME")},
			GCPProjectID: os.Getenv("GCP_PROJECT_ID"),
		},
	})
	if err != nil {
		log.Fatalf("Failed to create attestation server: %v", err)
	}
	defer server.Close()

	// Set up routes
	http.HandleFunc("/challenge", handleChallenge(server))
	http.HandleFunc("/attest", handleAttest(server))

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handleChallenge generates a new attestation challenge.
// GET /challenge?user_id=xxx
func handleChallenge(server *attestation.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			http.Error(w, "user_id is required", http.StatusBadRequest)
			return
		}

		challenge, err := server.GenerateChallenge(userID)
		if err != nil {
			http.Error(w, "Failed to generate challenge", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChallengeResponse{Challenge: challenge})
	}
}

// handleAttest verifies a device attestation.
// POST /attest?user_id=xxx
func handleAttest(server *attestation.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			http.Error(w, "user_id is required", http.StatusBadRequest)
			return
		}

		var req AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Verify attestation (challenge validation is handled automatically)
		result, err := server.VerifyAttestation(context.Background(), userID, attestation.VerifyRequest{
			Platform:    attestation.Platform(req.Platform),
			Attestation: req.Attestation,
			Challenge:   req.Challenge,
			KeyID:       req.KeyID,
			BundleID:    req.BundleID,
		})
		if err != nil {
			log.Printf("Attestation failed for user %s: %v", userID, err)
			http.Error(w, "Attestation verification failed", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AttestResponse{
			Valid:    result.Valid,
			DeviceID: result.DeviceID,
			Platform: string(result.Platform),
		})
	}
}
