package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidatePolicy(t *testing.T) {
	cases := map[string]struct {
		policy      Policy
		errContains string
	}{
		"valid policy": {
			policy: Policy{
				Issuer:        "http://localhost:8888",
				Algorithm:     "RS256",
				Subject:       nil,
				JwksURL:       "http://localhost:8888/.well-known/jwks.json",
				AllowedScopes: []string{"acls", "devices:read"},
			},
		},
		"missing issuer": {
			policy: Policy{
				Algorithm:     "RS256",
				Subject:       nil,
				JwksURL:       "http://localhost:8888/.well-known/jwks.json",
				AllowedScopes: []string{"acls", "devices:read"},
			},
			errContains: "no issuer",
		},
		"missing algorithm": {
			policy: Policy{
				Issuer:        "http://localhost:8888",
				Subject:       nil,
				JwksURL:       "http://localhost:8888/.well-known/jwks.json",
				AllowedScopes: []string{"acls", "devices:read"},
			},
			errContains: "unsupported algorithm",
		},
		"missing jwks url": {
			policy: Policy{
				Issuer:        "http://localhost:8888",
				Algorithm:     "RS256",
				Subject:       nil,
				AllowedScopes: []string{"acls", "devices:read"},
			},
			errContains: "no JWKS URL",
		},
		"missing allowed scopes": {
			policy: Policy{
				Issuer:    "http://localhost:8888",
				Algorithm: "RS256",
				Subject:   nil,
				JwksURL:   "http://localhost:8888/.well-known/jwks.json",
			},
			errContains: "no scopes",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidatePolicy(tc.policy)
			if tc.errContains == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
			}
		})
	}
}
