package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Ensuring that OAuthFetcher reaches out to a token endpoint with the expected parameters
func TestFetchAccessToken(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	scopes := []string{"devices:read", "acls"}
	expectedToken := "testToken"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		assert.NoError(err)

		assert.Equal("POST", r.Method)
		assert.Equal("client_credentials", r.PostForm.Get("grant_type"))
		assert.Equal(strings.Join(scopes, " "), r.PostForm.Get("scope"))

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write([]byte(fmt.Sprintf(`{"access_token": "%s", "token_type": "bearer", "expires_in": 3600}`, expectedToken)))
		assert.NoError(err)
	}))
	defer srv.Close()

	c := NewOAuthFetcher("testClientID", "testClientSecret", srv.URL)
	actualToken, err := c.Fetch(ctx, scopes)
	assert.NoError(err)
	assert.Equal(expectedToken, actualToken)
}
