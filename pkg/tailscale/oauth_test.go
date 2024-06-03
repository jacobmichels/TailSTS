package tailscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchAccessToken(t *testing.T) {
	ctx := context.Background()

	scopes := []string{"devices:read", "acls"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		assert.NoError(t, err)

		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		assert.Equal(t, strings.Join(scopes, " "), r.PostForm.Get("scope"))

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write([]byte(`{"access_token": "test", "token_type": "bearer", "expires_in": 3600}`))
		assert.NoError(t, err)
	}))
	defer srv.Close()

	c := NewClient("test", "test", srv.URL)
	token, err := c.Fetch(ctx, scopes)
	assert.NoError(t, err)
	assert.Equal(t, "test", token)
}
