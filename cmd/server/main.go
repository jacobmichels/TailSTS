package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jacobmichels/tail-sts/pkg/policy"
)

func main() {
	ctx := context.Background()

	policies := getPolicies(ctx)

	err := startServer(policies)
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

type Decider struct {
	Policies []policy.Policy
}

func (d *Decider) Decide(ctx context.Context, req Request, token jwt.Token) (bool, error) {

}

func startServer(policies []policy.Policy, decider Decider) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
			return
		}

		// It's possible to use jwt.ParseUnverified to parse the token without verifying the signature
		parser := jwt.NewParser()
		var claims jwt.RegisteredClaims
		parser.ParseUnverified(string(auth[7:]), &claims)

		token, err := jwt.Parse(string(auth[7:]), func(token *jwt.Token) (interface{}, error) {
			if token.Method.Alg() != jwt.SigningMethodRS256.Name {
				return nil, jwt.ErrInvalidKey
			}

			kid := token.Header["kid"].(string)
			if kid == "" {
				return nil, jwt.ErrInvalidKey
			}

			policy, err := matchPolicy(r.Context(), policies, kid)
			if err != nil {
				return nil, fmt.Errorf("failed to match policy: %w", err)
			}
			if policy == nil {
				return nil, errors.New("no matching policy")
			}

			return policy.Jwks.Keyfunc(token)
		})
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		var req Request
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	srv := http.Server{Addr: ":8080", Handler: mux}

	return srv.ListenAndServe()
}

func matchPolicy(ctx context.Context, policies []policy.Policy, kid string) (*policy.Policy, error) {
	for _, policy := range policies {
		jwks, err := policy.Jwks.Storage().KeyReadAll(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read keys: %w", err)
		}

		for _, jwk := range jwks {
			if jwk.Marshal().KID == kid {
				return &policy, nil
			}
		}
	}

	return nil, nil
}
