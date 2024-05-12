package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

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

func Start(policies []policy.Policy, tsClient tailscale.Client) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		// perform basic validation of the format of the request
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
			return
		}

		var req Request
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// parse the token without validating it
		// this is needed to read the issuer in order to find a matching policy
		parser := jwt.NewParser()
		var claims jwt.RegisteredClaims
		_, _, err = parser.ParseUnverified(string(auth[7:]), &claims)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// find the policy that matches the token's issuer
		policy := findByIssuer(policies, claims.Issuer)
		if policy == nil {
			http.Error(w, "no matching policy", http.StatusUnauthorized)
			return
		}

		// use that policy's JWKS to verify the token
		_, err = jwt.Parse(string(auth[7:]), func(token *jwt.Token) (any, error) {
			return policy.Jwks.Keyfunc(token)
		}, jwt.WithValidMethods([]string{policy.Algorithm}))

		if err != nil {
			switch {
			case errors.Is(err, jwt.ErrTokenMalformed):
				http.Error(w, "malformed token", http.StatusUnauthorized)
			case errors.Is(err, jwt.ErrTokenSignatureInvalid):
				http.Error(w, "invalid signature", http.StatusUnauthorized)
			case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
				http.Error(w, "token expired or not yet valid", http.StatusUnauthorized)
			default:
				http.Error(w, "cannot handle this token", http.StatusUnauthorized)
			}
			return
		}

		// token is validated and matches a policy
		// time to evaluate the requested scopes against the policy
		allowed := evaluate(*policy, req.Scopes)
		if !allowed {
			http.Error(w, "request denied", http.StatusForbidden)
			return
		}

		// get an access token from tailscale and return it
		accessToken, err := tsClient.Token(r.Context(), req.Scopes)
		if err != nil {
			fmt.Printf("failed to get tailscale token: %v\n", err)
			http.Error(w, "failed to get tailscale token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(map[string]string{"token": accessToken})
		if err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	srv := http.Server{Addr: ":8080", Handler: mux}

	return srv.ListenAndServe()
}
