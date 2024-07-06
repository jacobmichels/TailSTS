package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacobmichels/tail-sts/pkg/jwks"
	"github.com/jacobmichels/tail-sts/pkg/policy"
	"github.com/jacobmichels/tail-sts/pkg/server"
	"github.com/jacobmichels/tail-sts/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestTailstsIntegration(t *testing.T) {
	logger := testLogger(t)
	kid := "test"
	subject := "anakin"
	accessToken := "ts-access-token"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuerURL, localJWKSUrl := spawnJwksServer(t, logger, key, kid)

	token, err := jwks.GenerateToken(key, issuerURL, subject, kid)
	require.NoError(t, err)

	policies := testPolicies(t, issuerURL, localJWKSUrl, subject)

	staticFetcher := &testutils.StaticFetcher{AccessToken: accessToken}
	verif := server.JWKSVerifier{}
	handler := server.NewTokenRequestHandler(logger, policies, staticFetcher, verif)

	cases := map[string]struct {
		scopesJson         string
		expectedStatusCode int
	}{
		"allowed scopes": {
			scopesJson:         `{"scopes":["devices:read", "acls"]}`,
			expectedStatusCode: http.StatusOK,
		},
		"missing scope": {
			scopesJson:         `{"scopes":["all"]}`,
			expectedStatusCode: http.StatusForbidden,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.scopesJson))
			req.Header.Add("Authorization", "Bearer "+token)

			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)
			require.Equal(recorder.Result().StatusCode, tc.expectedStatusCode)

			if tc.expectedStatusCode == http.StatusOK {
				token := recorder.Body.String()
				require.NotNil(token)
				require.Equal(token, accessToken)
			}
		})
	}
}

func spawnJwksServer(t *testing.T, logger *slog.Logger, key *rsa.PrivateKey, kid string) (string, string) {
	t.Helper()

	handler := jwks.NewJWKSHandler(logger, key, kid)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return srv.URL, srv.URL + "/jwks"
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()

	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

func testPolicies(t *testing.T, issuerURL, localJWKSUrl, subject string) policy.PolicyList {
	t.Helper()

	p := policy.Policy{

		Issuer:        issuerURL,
		Algorithm:     "RS256",
		Subject:       &subject,
		JwksURL:       localJWKSUrl,
		AllowedScopes: []string{"devices:read", "acls"},
	}
	err := p.LoadJwks(context.Background())
	require.NoError(t, err)

	return policy.PolicyList{
		p,
	}
}
