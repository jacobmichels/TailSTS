package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/jacobmichels/tail-sts/pkg/jwks"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "JWKS Server",
		Usage: "Spin up a server that serves a JWKS endpoint with a single keypair",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "port",
				Usage:   "Port to listen on",
				EnvVars: []string{"PORT"},
				Value:   8888,
			},
			&cli.StringFlag{
				Name:    "issuer",
				Usage:   "Issuer to use in the generated token",
				EnvVars: []string{"ISSUER"},
				Value:   "http://localhost:8888",
			},
			&cli.StringFlag{
				Name:    "subject",
				Usage:   "Subject to use in the generated token",
				EnvVars: []string{"SUBJECT"},
				Value:   "test",
			},
			&cli.StringFlag{
				Name:    "kid",
				Usage:   "KID to use in the JWKS",
				EnvVars: []string{"SUBJECT"},
				Value:   "test",
			},
		},
		Action: func(c *cli.Context) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			return run(c, logger)
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func run(c *cli.Context, logger *slog.Logger) error {
	port := c.Int("port")
	issuer := c.String("issuer")
	subject := c.String("subject")
	kid := c.String("kid")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	logger.Debug("Generated RSA keypair")

	token, err := jwks.GenerateToken(key, issuer, subject, kid)
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}
	logger.Debug("Generated JWT", "token", token, "issuer", issuer, "subject", subject)

	mux := jwks.NewJWKSHandler(logger, key, kid)
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	logger.Info("Server listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited with an error", "error", err)
	}

	return nil
}
