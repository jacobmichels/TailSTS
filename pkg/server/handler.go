package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jacobmichels/tail-sts/pkg/policy"
)

type Request struct {
	Scopes []string
}

type Response struct {
	Token string `json:"token"`
}

func NewTokenRequestHandler(logger *slog.Logger, policies policy.PolicyList, ts AccessTokenFetcher, verif OIDCTokenVerifier) http.Handler {
	mux := http.NewServeMux()

	handler := func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Request received")

		// perform basic validation of the format of the request
		auth := r.Header.Get("Authorization")
		if auth == "" {
			logger.Debug("Request missing Authorization header")
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			logger.Debug("Request missing Bearer prefix")
			http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
			return
		}

		var req Request
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			logger.Debug("Failed to decode request", "error", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		logger.Debug("Request decoded", "scopes", req.Scopes)

		if len(req.Scopes) == 0 {
			logger.Debug("Request missing scopes")
			http.Error(w, "missing scopes", http.StatusBadRequest)
			return
		}

		// parse the token without validating it
		// this is needed to read the issuer in order to find a matching policy
		parser := jwt.NewParser()
		var claims jwt.RegisteredClaims
		_, _, err = parser.ParseUnverified(string(auth[7:]), &claims)
		if err != nil {
			logger.Debug("Failed to parse token", "error", err)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// find the policy that matches the token's issuer
		policy := policies.FindByIssuer(claims.Issuer)
		if policy == nil {
			logger.Debug("No matching policy", "issuer", claims.Issuer)
			http.Error(w, "no matching policy", http.StatusUnauthorized)
			return
		}

		logger.Debug("Matching policy found", "issuer", claims.Issuer, "allowedScopes", policy.AllowedScopes)

		// use that policy's JWKS to verify the token
		err = verif.Verify(string(auth[7:]), policy.Algorithm, policy.Jwks)
		if err != nil {
			switch {
			case errors.Is(err, jwt.ErrTokenMalformed):
				logger.Debug("Malformed token", "error", err)
				http.Error(w, "malformed token", http.StatusUnauthorized)
			case errors.Is(err, jwt.ErrTokenSignatureInvalid):
				logger.Debug("Invalid signature", "error", err)
				http.Error(w, "invalid signature", http.StatusUnauthorized)
			case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
				logger.Debug("Token expired or not yet valid", "error", err)
				http.Error(w, "token expired or not yet valid", http.StatusUnauthorized)
			default:
				logger.Debug("Cannot handle this token", "error", err)
				http.Error(w, "cannot handle this token", http.StatusUnauthorized)
			}
			return
		}

		logger.Debug("Token signature validated")

		if policy.Subject == nil {
			logger.Debug("No subject specified in policy, allowing any subject")
		} else if claims.Subject != *policy.Subject {
			logger.Debug("Subject mismatch", "expected", *policy.Subject, "actual", claims.Subject)
			http.Error(w, "subject mismatch", http.StatusForbidden)
			return
		}

		logger.Debug("Subject validated")

		// token is validated and matches a policy
		// time to evaluate the requested scopes against the policy
		allowed := policy.Satisfied(req.Scopes)
		if !allowed {
			logger.Debug("Request denied", "requestedScopes", req.Scopes, "allowedScopes", policy.AllowedScopes)
			http.Error(w, "request denied", http.StatusForbidden)
			return
		}

		logger.Debug("Request allowed, fetching tailscale access token", "requestedScopes", req.Scopes, "allowedScopes", policy.AllowedScopes)

		accessToken, err := ts.Fetch(r.Context(), req.Scopes)
		if err != nil {
			logger.Error("Failed to get tailscale token", "error", err)
			http.Error(w, "failed to get tailscale token", http.StatusInternalServerError)
			return
		}

		logger.Debug("Access token acquired")

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, err = w.Write([]byte(accessToken))
		if err != nil {
			logger.Error("Failed to send response", "error", err)
			return
		}

		logger.Debug("Response sent")
	}

	mux.HandleFunc("POST /", handler)
	return mux
}
