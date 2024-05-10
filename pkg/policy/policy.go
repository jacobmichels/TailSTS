package policy

import (
	"context"
	"fmt"
	"os"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/pelletier/go-toml/v2"
)

type Policy struct {
	Issuers       []string `toml:"issuer"`
	Algorithm     string   `toml:"algorithm"`
	Subject       string   `toml:"subject"`
	JwksURL       string   `toml:"jwks_url"`
	Jwks          keyfunc.Keyfunc
	AllowedScopes map[string]string `toml:"allowed_scopes"`
}

func (p *Policy) LoadJwks(ctx context.Context) error {
	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{p.JwksURL})
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	p.Jwks = jwks
	return nil
}

func ReadPoliciesFromDir(dir string) ([]Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var policies []Policy
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		policy, err := readPolicyFromFile(dir + "/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read policy: %w", err)
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

func readPolicyFromFile(filename string) (Policy, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return Policy{}, fmt.Errorf("failed to read file: %w", err)
	}

	var policy Policy
	err = toml.Unmarshal(contents, &policy)
	if err != nil {
		return Policy{}, fmt.Errorf("failed to unmarshal TOML: %w", err)
	}

	return policy, nil
}
