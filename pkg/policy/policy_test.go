package policy

import (
	"testing"
)

func TestSatisfied(t *testing.T) {
	defaultPolicy := Policy{
		AllowedScopes: []string{"devices:read", "acls"},
	}

	cases := map[string]struct {
		policy          Policy
		requestedScopes []string
		policySatisfied bool
	}{
		"policies are not satisfied by empty requested scopes": {
			policy:          defaultPolicy,
			requestedScopes: []string{},
			policySatisfied: false,
		},
		"requesting one of the allowed scopes satisfies the policy": {
			policy:          defaultPolicy,
			requestedScopes: []string{"devices:read"},
			policySatisfied: true,
		},
		"requesting all of the allowed scopes satisfies the policy": {
			policy:          defaultPolicy,
			requestedScopes: []string{"devices:read", "acls"},
			policySatisfied: true,
		},
		"requesting a scope not allowed by the policy": {
			policy:          defaultPolicy,
			requestedScopes: []string{"users:read", "among:us"},
			policySatisfied: false,
		},
		"requesting multiple scopes, with one being not allowed by the policy": {
			policy:          defaultPolicy,
			requestedScopes: []string{"devices:read", "acls", "users:read"},
			policySatisfied: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got, want := tc.policy.Satisfied(tc.requestedScopes), tc.policySatisfied; got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}
