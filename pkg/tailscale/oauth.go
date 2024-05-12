package tailscale

import (
	"context"

	"golang.org/x/oauth2/clientcredentials"
)

type Client struct {
	config clientcredentials.Config
}

type ClientOption func(*Client)

func WithTokenURL(tokenURL string) ClientOption {
	return func(c *Client) {
		c.config.TokenURL = tokenURL
	}
}

func NewClient(clientID, clientSecret string, opts ...ClientOption) Client {
	c := Client{
		config: clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
		},
	}

	for _, opt := range opts {
		opt(&c)
	}

	return c
}

func (c *Client) Token(ctx context.Context, scopes []string) (string, error) {
	c.config.Scopes = scopes
	token, err := c.config.Token(ctx)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
