package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jacobmichels/tail-sts/pkg/policy"
	"github.com/jacobmichels/tail-sts/pkg/tailscale"
)

type Request struct {
	Scopes []string
}

func evaluate(policy policy.Policy, requestedScopes []string) bool {
	for _, requestedScope := range requestedScopes {
		if !slices.Contains(policy.AllowedScopes, requestedScope) {
			return false
		}
	}

	return true
}

func findByIssuer(policies []policy.Policy, issuer string) *policy.Policy {
	for _, policy := range policies {
		if slices.Contains(policy.Issuers, issuer) {
			return &policy
		}
	}

	return nil
}

func Start(ctx context.Context, logger slog.Logger, policies []policy.Policy, tsClient tailscale.Client, port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
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
		policy := findByIssuer(policies, claims.Issuer)
		if policy == nil {
			logger.Debug("No matching policy", "issuer", claims.Issuer)
			http.Error(w, "no matching policy", http.StatusUnauthorized)
			return
		}

		logger.Debug("Matching policy found", "issuer", claims.Issuer, "allowedScopes", policy.AllowedScopes)

		// use that policy's JWKS to verify the token
		_, err = jwt.Parse(string(auth[7:]), func(token *jwt.Token) (any, error) {
			return policy.Jwks.Keyfunc(token)
		}, jwt.WithValidMethods([]string{policy.Algorithm}))

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

		logger.Debug("Token signature validated, evaluating requested scopes against matched policy")

		// token is validated and matches a policy
		// time to evaluate the requested scopes against the policy
		allowed := evaluate(*policy, req.Scopes)
		if !allowed {
			logger.Debug("Request denied", "requestedScopes", req.Scopes, "allowedScopes", policy.AllowedScopes)
			http.Error(w, "request denied", http.StatusForbidden)
			return
		}

		logger.Debug("Request allowed, fetching tailscale access token", "requestedScopes", req.Scopes, "allowedScopes", policy.AllowedScopes)

		accessToken, err := tsClient.Token(r.Context(), req.Scopes)
		if err != nil {
			logger.Error("Failed to get tailscale token", "error", err)
			http.Error(w, "failed to get tailscale token", http.StatusInternalServerError)
			return
		}

		logger.Debug("Access token acquired")

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(map[string]string{"token": accessToken})
		if err != nil {
			logger.Error("Failed to encode response", "error", err)
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}

		logger.Debug("Response sent")
	})

	addr := fmt.Sprintf(":%d", port)

	logger.Info("Server listening", "addr", addr)
	srv := http.Server{Addr: addr, Handler: mux}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		if err := http.ListenAndServe(addr, srv.Handler); err != http.ErrServerClosed {
			logger.Error("server exited with an error", "error", err)
		}
	}()

	<-interrupt

	logger.Debug("interrupt signal received")

	ctx, cancel := context.WithTimeout(ctx, time.Second*15)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("error attempting to shutdown server", "error", err)
	}
}
