package jwks

import (
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/MicahParks/jwkset"
)

type JWKSResponse struct {
	Keys []jwkset.JWKMarshal `json:"keys"`
}

func NewJWKSHandler(logger *slog.Logger, key *rsa.PrivateKey, kid string) http.Handler {
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Handling JWKS request")

		jwk, err := jwkset.NewJWKFromKey(key, jwkset.JWKOptions{Metadata: jwkset.JWKMetadataOptions{
			KID: kid,
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
	}

	mux.HandleFunc("GET /jwks", handler)
	return mux
}
