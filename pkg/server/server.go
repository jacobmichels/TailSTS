package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jacobmichels/tail-sts/pkg/policy"
	"github.com/jacobmichels/tail-sts/pkg/tailscale"
)

func Start(ctx context.Context, logger *slog.Logger, policies []policy.Policy, ts tailscale.AccessTokenFetcher, port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", tokenRequestHandler(logger, policies, ts))

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
