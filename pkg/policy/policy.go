package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
)

type Policy struct {
	Issuers       []string `toml:"issuer"`
	Algorithm     string   `toml:"algorithm"`
	Subject       string   `toml:"subject"`
	JwksURL       string   `toml:"jwks_url"`
	Jwks          keyfunc.Keyfunc
	AllowedScopes []string `toml:"allowed_scopes"`
}

func (p *Policy) LoadJwks(ctx context.Context) error {
	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{p.JwksURL})
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	if jwks == nil {
		return errors.New("failed to get JWKS")
	}

	p.Jwks = jwks

	return nil
}

func GetPolicies(ctx context.Context, dir string) ([]Policy, error) {
	policies, err := ReadFromDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read policies from dir %s: %w", dir, err)
	}

	var loadJWKSErrors error
	for i := range policies {
		policy := &policies[i]
		err := policy.LoadJwks(ctx)
		if err != nil {
			loadJWKSErrors = errors.Join(loadJWKSErrors, fmt.Errorf("failed to load JWKS for policy: %w", err))
		}
	}

	if loadJWKSErrors != nil {
		return nil, loadJWKSErrors
	}

	return policies, nil
}
