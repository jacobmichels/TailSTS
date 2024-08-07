package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jacobmichels/tail-sts/pkg/policy"
	"github.com/jacobmichels/tail-sts/pkg/testutils"
)

var _ AccessTokenFetcher = (*testutils.StaticFetcher)(nil)

// An OIDCTokenVerifier that always returns its wrapped error
type StaticVerifier struct {
	err error
}

var _ OIDCTokenVerifier = (*StaticVerifier)(nil)

func (s *StaticVerifier) Verify(token, alg string, kf keyfunc.Keyfunc) error {
	return s.err
}

var defaultSubject string = "test-subject"

const defaultIssuer = "https://example.com"
const fakeAccessToken = "mock-access-token"

func TestTokenRequestHandler(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	ts := &testutils.StaticFetcher{AccessToken: fakeAccessToken}

	cases := map[string]struct {
		token                string
		requestedScopes      []string
		expectedStatus       int
		expectedErrorMessage string
		policies             policy.PolicyList
		verif                OIDCTokenVerifier
	}{
		"requested scopes = allowed scopes, matching subject": {
			requestedScopes: []string{
				"scope1",
				"scope2",
			},
			expectedStatus: 200,
			token:          generateToken(t, defaultIssuer, defaultSubject),
			policies: policy.PolicyList{
				{
					Issuer:        "https://example.com",
					AllowedScopes: []string{"scope1", "scope2"},
					Subject:       &defaultSubject,
				},
			},
			verif: &StaticVerifier{err: nil},
		},
		"requested scopes < allowed scopes": {
			requestedScopes: []string{
				"scope1",
			},
			token:          generateToken(t, defaultIssuer, defaultSubject),
			expectedStatus: 200,
			policies: policy.PolicyList{
				{
					Issuer:        "https://example.com",
					AllowedScopes: []string{"scope1", "scope2"},
				},
			},
			verif: &StaticVerifier{err: nil},
		},
		"no requested scopes": {
			requestedScopes:      []string{},
			expectedStatus:       400,
			expectedErrorMessage: "missing scopes",
		},
		"requested scopes > allowed scopes": {
			requestedScopes: []string{
				"scope1",
				"scope2",
				"scope3",
			},
			token:          generateToken(t, defaultIssuer, defaultSubject),
			expectedStatus: 403,
			policies: policy.PolicyList{
				{
					Issuer:        "https://example.com",
					AllowedScopes: []string{"scope1", "scope2"},
				},
			},
			expectedErrorMessage: "request denied",
			verif:                &StaticVerifier{err: nil},
		},
		"mismatched subject": {
			requestedScopes: []string{
				"scope1",
				"scope2",
			},
			token:          generateToken(t, defaultIssuer, "wrong-subject"),
			expectedStatus: 403,
			policies: policy.PolicyList{
				{
					Issuer:        "https://example.com",
					AllowedScopes: []string{"scope1", "scope2"},
					Subject:       &defaultSubject,
				},
			},
			expectedErrorMessage: "subject mismatch",
			verif:                &StaticVerifier{err: nil},
		},
		"no matching policy": {
			requestedScopes: []string{
				"scope1",
				"scope2",
			},
			expectedStatus:       401,
			expectedErrorMessage: "no matching policy",
			policies:             policy.PolicyList{},
		},
		"invalid token": {
			requestedScopes: []string{
				"scope1",
				"scope2",
			},
			expectedStatus:       401,
			expectedErrorMessage: "invalid token",
			policies: policy.PolicyList{
				{
					Issuer:        "https://example.com",
					AllowedScopes: []string{"scope1", "scope2"},
				},
			},
			verif: &StaticVerifier{err: jwt.ErrTokenMalformed},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			handler := NewTokenRequestHandler(log, tc.policies, ts, tc.verif)

			var body bytes.Buffer
			err := json.NewEncoder(&body).Encode(Request{Scopes: tc.requestedScopes})
			if err != nil {
				t.Fatalf("failed to encode request body: %v", err)
			}

			req := httptest.NewRequest("POST", "/", &body)

			req.Header.Set("Authorization", "Bearer "+tc.token)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d. error message: %s", tc.expectedStatus, w.Code, w.Body.String())
			}

			if w.Code == 200 {
				token := w.Body.String()

				if token == "" {
					t.Error("expected non-empty token in response")
				}

				if token != fakeAccessToken {
					t.Errorf("expected token %q, got %q", fakeAccessToken, token)
				}
			}
		})
	}
}

func generateToken(t *testing.T, issuer, sub string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": issuer,
		"sub": sub,
	})

	signed, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return signed
}
