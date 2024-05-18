package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"time"

	"github.com/jacobmichels/tail-sts/pkg/policy"
	"github.com/jacobmichels/tail-sts/pkg/tailscale"
)

type Request struct {
	Scopes []string
}

func evaluate(policy policy.Policy, requestedScopes []string) bool {
	for _, requestedScope := range requestedScopes {
		if !slices.Contains(policy.AllowedScopes, requestedScope) {
			return false
		}
	}

	return true
}

func findByIssuer(policies []policy.Policy, issuer string) *policy.Policy {
	for _, policy := range policies {
		if slices.Contains(policy.Issuers, issuer) {
			return &policy
		}
	}

	return nil
}

func Start(ctx context.Context, logger slog.Logger, policies []policy.Policy, tsClient tailscale.Client, port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", tokenRequestHandler(logger, policies, tsClient))

	addr := fmt.Sprintf(":%d", port)

	logger.Info("Server listening", "addr", addr)
	srv := http.Server{Addr: addr, Handler: mux}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		if err := http.ListenAndServe(addr, srv.Handler); err != http.ErrServerClosed {
			logger.Error("server exited with an error", "error", err)
		}
	}()

	<-interrupt

	logger.Debug("interrupt signal received")

	ctx, cancel := context.WithTimeout(ctx, time.Second*15)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("error attempting to shutdown server", "error", err)
	}
}
