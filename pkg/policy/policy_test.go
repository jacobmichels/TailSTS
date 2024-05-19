package policy

import (
	"testing"
)

func TestSatisfied(t *testing.T) {
	p := Policy{
		AllowedScopes: []string{"devices:read", "acls"},
	}

	tests := map[string]struct {
		requestedScopes []string
		expected        bool
	}{
		"empty requested scopes": {
			requestedScopes: []string{},
			expected:        true,
		},
		"single requested scope": {
			requestedScopes: []string{"devices:read"},
			expected:        true,
		},
		"multiple requested scopes": {
			requestedScopes: []string{"devices:read", "acls"},
			expected:        true,
		},
		"missing requested scope": {
			requestedScopes: []string{"devices:read", "acls", "users:read"},
			expected:        false,
		},
		"no allowed scopes": {
			requestedScopes: []string{"users:read", "among:us"},
			expected:        false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got, want := p.Satisfied(test.requestedScopes), test.expected; got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestReadFromDir(t *testing.T) {
	policiesDir := "testdata/policies"

	expectedPolicies := []Policy{
		{
			Issuers:       []string{"http://localhost:8888"},
			Algorithm:     "RS256",
			JwksURL:       "http://localhost:8888/.well-known/jwks.json",
			AllowedScopes: []string{"acls", "devices:read"},
			Subject:       "",
		},
		{
			Issuers:       []string{"http://localhost:8888"},
			Algorithm:     "RS256",
			JwksURL:       "http://localhost:8888/jwks",
			AllowedScopes: []string{"routes", "logs:read"},
			Subject:       "test",
		},
	}

	policies, err := ReadFromDir(policiesDir)
	if err != nil {
		t.Fatalf("failed to get policies: %v", err)
	}

	if got, want := len(policies), len(expectedPolicies); got != want {
		t.Fatalf("got %d policies, want %d", got, want)
	}

	for i, policy := range policies {
		got, want := policy, expectedPolicies[i]
		comparePolicies(t, got, want)
	}

}

func comparePolicies(t *testing.T, got, want Policy) {
	t.Helper()

	if len(got.Issuers) != len(want.Issuers) {
		t.Errorf("got %d issuers, want %d", len(got.Issuers), len(want.Issuers))
	} else {
		for i, issuer := range got.Issuers {
			if issuer != want.Issuers[i] {
				t.Errorf("got issuer %q, want %q", issuer, want.Issuers[i])
			}
		}
	}

	if got.Algorithm != want.Algorithm {
		t.Errorf("got algorithm %q, want %q", got.Algorithm, want.Algorithm)
	}

	if got.JwksURL != want.JwksURL {
		t.Errorf("got jwks url %q, want %q", got.JwksURL, want.JwksURL)
	}

	if got.Subject != want.Subject {
		t.Errorf("got subject %q, want %q", got.Subject, want.Subject)
	}

	if len(got.AllowedScopes) != len(want.AllowedScopes) {
		t.Errorf("got %d allowed scopes, want %d", len(got.AllowedScopes), len(want.AllowedScopes))
	} else {
		for i, scope := range got.AllowedScopes {
			if scope != want.AllowedScopes[i] {
				t.Errorf("got allowed scope %q, want %q", scope, want.AllowedScopes[i])
			}
		}
	}
}

func TestLoadJwks(t *testing.T) {
	t.Skip("not implemented")
}
