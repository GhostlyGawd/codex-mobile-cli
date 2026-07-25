package githubapp

import (
	"context"
	"errors"
)

// TokenBroker gives the in-process Git transport a short-lived mutable copy of
// an installation token. Authenticated Git operations must never place this
// value, or a path to it, in a subprocess environment, argv, remote URL, or
// repository configuration: every executable and config file in a workspace
// is hostile.
type TokenBroker struct {
	Token string
}

func (b TokenBroker) Credential(ctx context.Context) ([]byte, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if b.Token == "" || len(b.Token) > 1024 {
		return nil, nil, errors.New("GitHub installation token is required")
	}
	value := []byte(b.Token)
	cleanup := func() { clear(value) }
	return value, cleanup, nil
}
