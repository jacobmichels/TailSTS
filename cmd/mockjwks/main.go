package main

import (
	"log/slog"
	"os"

	"github.com/jacobmichels/tail-sts/pkg/jwksmock"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "Mock JWKS Server",
		Usage: "Generate tokens and serve a JWKS endpoint for testing OIDC flows",
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

	_, err := jwksmock.StartTestingServer(logger, port, issuer, subject)
	if err != nil {
		return err
	}

	return nil
}
