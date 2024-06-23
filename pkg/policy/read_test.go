package policy

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFromDir(t *testing.T) {
	subject := "test"

	policy1 := Policy{
		Issuer:        "http://localhost:8888",
		Algorithm:     "RS256",
		JwksURL:       "http://localhost:8888/.well-known/jwks.json",
		AllowedScopes: []string{"acls", "devices:read"},
		Subject:       nil,
	}
	policy2 := Policy{
		Issuer:        "http://localhost:8080",
		Algorithm:     "RS256",
		JwksURL:       "http://localhost:8888/jwks",
		AllowedScopes: []string{"routes", "logs:read"},
		Subject:       &subject,
	}
	policy3 := Policy{
		Issuer:        "http://localhost:123",
		Algorithm:     "RS256",
		JwksURL:       "http://localhost:123/jwks.json",
		AllowedScopes: []string{"all"},
	}

	cases := map[string]struct {
		dir              string
		err              string
		expectedPolicies PolicyList
	}{
		"empty directory": {
			dir:              "testdata/empty",
			err:              "no policies found in directory",
			expectedPolicies: nil,
		},
		"single policy": {
			dir: "testdata/single_policy",
			err: "",
			expectedPolicies: PolicyList{
				policy1,
			},
		},
		"multiple policies": {
			dir: "testdata/multiple_policies",
			err: "",
			expectedPolicies: PolicyList{
				policy1,
				policy2,
				policy3,
			},
		},
		"directory not found": {
			dir:              "testdata/non_existent",
			err:              "failed to read directory",
			expectedPolicies: nil,
		},
		"invalid policy": {
			dir:              "testdata/invalid_policy",
			err:              "failed to unmarshal TOML",
			expectedPolicies: nil,
		},
		"mixed valid and invalid policies": {
			dir:              "testdata/mixed_valid_invalid",
			err:              "failed to read policy",
			expectedPolicies: nil,
		},
		"nested directories, only top-level directory examined": {
			dir: "testdata/nested",
			err: "",
			expectedPolicies: PolicyList{
				policy1,
			},
		},
	}

	assert := assert.New(t)
	require := require.New(t)
	err := os.MkdirAll("testdata/empty", 0755)
	require.NoError(err)
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			policies, err := ReadFromDir(tc.dir)
			if tc.err == "" {
				assert.NoError(err)

				expectedPolicyCount := len(tc.expectedPolicies)
				actualPolicyCount := len(policies)
				assert.Equal(expectedPolicyCount, actualPolicyCount, "expected %d policies, got %d", expectedPolicyCount, actualPolicyCount)

				// os.ReadDir sorts by filename, so we can compare policies in order
				for i, expectedPolicy := range tc.expectedPolicies {
					assertPolicyEqual(assert, expectedPolicy, policies[i])
				}
			} else {
				require.Error(err)
				assert.Contains(err.Error(), tc.err)
			}
		})
	}
}

func assertPolicyEqual(assert *assert.Assertions, expectedPolicy, policy Policy) {
	assert.Equal(expectedPolicy.Issuer, policy.Issuer)
	assert.Equal(expectedPolicy.Algorithm, policy.Algorithm)
	assert.Equal(expectedPolicy.JwksURL, policy.JwksURL)
	assert.Equal(expectedPolicy.AllowedScopes, policy.AllowedScopes)
	assert.Equal(expectedPolicy.Subject, policy.Subject)
}
