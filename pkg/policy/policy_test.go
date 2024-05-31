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
