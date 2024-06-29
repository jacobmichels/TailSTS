package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jacobmichels/tail-sts/pkg/policy"
	"github.com/jacobmichels/tail-sts/pkg/server"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "TailSTS",
		Usage: "Federate Tailscale with OIDC",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "ts-client-id",
				Usage:   "Tailscale client ID",
				EnvVars: []string{"TS_CLIENT_ID"},
			},
			&cli.StringFlag{
				Name:    "ts-client-secret",
				Usage:   "Tailscale client secret",
				EnvVars: []string{"TS_CLIENT_SECRET"},
			},
			&cli.StringFlag{
				Name:    "ts-token-url",
				Usage:   "Tailscale token URL",
				EnvVars: []string{"TS_TOKEN_URL"},
				Value:   "https://api.tailscale.com/api/v2/oauth/token",
			},
			&cli.StringFlag{
				Name:    "policies-dir",
				Usage:   "Directory containing policy files",
				EnvVars: []string{"POLICIES_DIR"},
				Value:   "policies",
			},
			&cli.BoolFlag{
				Name:    "json-logging",
				Usage:   "Enable JSON logging",
				EnvVars: []string{"JSON_LOGGING"},
			},
			&cli.IntFlag{
				Name:    "port",
				Usage:   "Port to listen on",
				EnvVars: []string{"PORT"},
				Value:   8080,
			},
		},
		Action: func(c *cli.Context) error {
			var logger *slog.Logger
			if c.Bool("json-logging") {
				logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				}))
			} else {
				logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				}))
			}

			return run(c, logger)
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func run(c *cli.Context, logger *slog.Logger) error {
	ctx := c.Context
	logger.Info("TailSTS warming up")

	logger.Debug("Loading policies")
	policies, err := policy.GetPolicies(ctx, c.String("policies-dir"))
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}
	logger.Debug("Policies loaded", "count", len(policies))

	err = policy.ValidatePolicies(policies)
	if err != nil {
		return fmt.Errorf("failed to validate policies: %w", err)
	}

	tsClient := server.NewOAuthFetcher(c.String("ts-client-id"), c.String("ts-client-secret"), c.String("ts-token-url"))
	verif := server.JWKSVerifier{}

	logger.Debug("Dependencies initialized, preparing server")
	port := c.Int("port")

	handler := server.NewTokenRequestHandler(logger, policies, tsClient, verif)
	server.Start(ctx, logger, handler, port)

	logger.Info("Server shutdown")

	return nil
}
