package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func StartServer(ctx context.Context, logger *slog.Logger, handler http.Handler, port int) {
	addr := fmt.Sprintf(":%d", port)
	srv := &http.Server{Addr: addr, Handler: handler}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		logger.Info("Server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
