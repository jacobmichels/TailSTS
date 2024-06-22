package server

import (
	"context"

	"golang.org/x/oauth2/clientcredentials"
)

type OAuthFetcher struct {
	config clientcredentials.Config
}

var _ AccessTokenFetcher = (*OAuthFetcher)(nil)

func NewOAuthFetcher(clientID, clientSecret, tokenURL string) *OAuthFetcher {
	return &OAuthFetcher{
		config: clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
		},
	}
}

func (c *OAuthFetcher) Fetch(ctx context.Context, scopes []string) (string, error) {
	c.config.Scopes = scopes
	token, err := c.config.Token(ctx)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
