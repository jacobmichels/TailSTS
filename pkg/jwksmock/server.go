package jwksmock

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

type JWKSResponse struct {
	Keys []jwkset.JWKMarshal `json:"keys"`
}

func StartTestingServer(logger *slog.Logger, port int, issuer, subject string) (string, error) {
	// generate an RSA keypair
	secret, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate keypair: %w", err)
	}

	logger.Debug("Generated RSA keypair")

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": subject,
		"iss": issuer,
	})
	token.Header["kid"] = "test"
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	logger.Info("Generated JWT", "token", signed)

	http.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Handling JWKS request")

		jwk, err := jwkset.NewJWKFromKey(secret, jwkset.JWKOptions{Metadata: jwkset.JWKMetadataOptions{
			KID: "test",
		}})
		if err != nil {
			logger.Error("failed to create JWK", "error", err)
			http.Error(w, "failed to create JWK", http.StatusInternalServerError)
			return
		}

		var response JWKSResponse
		response.Keys = append(response.Keys, jwk.Marshal())
		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			logger.Error("failed to write response", "error", err)
			return
		}
	})

	logger.Info("Serving JWKS at /jwks", "port", port, "issuer", issuer)

	err = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil && err != http.ErrServerClosed {
		return "", fmt.Errorf("server failure: %w", err)
	}

	return signed, nil
}
