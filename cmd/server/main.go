package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jacobmichels/tail-sts/pkg/policy"
)

func main() {
	ctx := context.Background()

	policies := getPolicies(ctx)
	decider := GateKeeper{Policies: policies}

	err := startServer(policies, decider)
	if err != nil {
		panic(err)
	}
}

func getPolicies(ctx context.Context) []policy.Policy {
	policies, err := policy.ReadPoliciesFromDir("policies")
	if err != nil {
		panic(err)
	}

	for _, policy := range policies {
		err := policy.LoadJwks(ctx)
		if err != nil {
			panic(err)
		}
	}

	return policies
}

type Request struct {
	Scopes map[string]string
}

type GateKeeper struct {
	Policies []policy.Policy
}

func (d *GateKeeper) Evaluate(ctx context.Context, req Request, token jwt.Token) (bool, error) {
	return false, nil
}

func startServer(policies []policy.Policy, decider GateKeeper) error {
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
		policy := findByIssuer(r.Context(), policies, claims.Issuer)
		if policy == nil {
			http.Error(w, "no matching policy", http.StatusUnauthorized)
			return
		}

		// use that policy's JWKs to verify the token
		token, err := jwt.Parse(string(auth[7:]), func(token *jwt.Token) (any, error) {
			return policy.Jwks.Keyfunc(token)
		}, jwt.WithValidMethods([]string{policy.Algorithm}))

		switch {
		case token.Valid:
			w.Write([]byte("OK"))
		case errors.Is(err, jwt.ErrTokenMalformed):
			http.Error(w, "malformed token", http.StatusUnauthorized)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			http.Error(w, "invalid signature", http.StatusUnauthorized)
		case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
			http.Error(w, "token expired or not yet valid", http.StatusUnauthorized)
		default:
			http.Error(w, "cannot handle this token", http.StatusUnauthorized)
		}
	})

	srv := http.Server{Addr: ":8080", Handler: mux}

	return srv.ListenAndServe()
}

func findByIssuer(ctx context.Context, policies []policy.Policy, issuer string) *policy.Policy {
	for _, policy := range policies {
		if slices.Contains(policy.Issuers, issuer) {
			return &policy
		}
	}

	return nil
}

func findKeyForKID(ctx context.Context, policy policy.Policy, kid string) (*jwkset.JWK, error) {
	keys, err := policy.Jwks.Storage().KeyReadAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys: %w", err)
	}

	for _, key := range keys {
		if key.Marshal().KID == kid {
			return &key, nil
		}
	}

	return nil, nil

}
