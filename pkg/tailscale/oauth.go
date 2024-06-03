package tailscale

import (
	"context"

	"golang.org/x/oauth2/clientcredentials"
)

type AccessTokenFetcher interface {
	Fetch(ctx context.Context, scopes []string) (string, error)
}

type OauthFetcher struct {
	config clientcredentials.Config
}

var _ AccessTokenFetcher = (*OauthFetcher)(nil)

func NewClient(clientID, clientSecret, tokenURL string) *OauthFetcher {
	return &OauthFetcher{
		config: clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
		},
	}
}

func (c *OauthFetcher) Fetch(ctx context.Context, scopes []string) (string, error) {
	c.config.Scopes = scopes
	token, err := c.config.Token(ctx)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
