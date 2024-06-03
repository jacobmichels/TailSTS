package tailscale

import "context"

type AccessTokenFetcher interface {
	Fetch(ctx context.Context, scopes []string) (string, error)
}
