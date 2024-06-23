package testutils

import (
	"context"
)

// An AccessTokenFetcher that always returns the same token
type StaticFetcher struct {
	AccessToken string
}

func (s *StaticFetcher) Fetch(ctx context.Context, scopes []string) (string, error) {
	return s.AccessToken, nil
}
