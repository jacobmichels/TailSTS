package main

import (
	"fmt"
	"os"

	"github.com/jacobmichels/tail-sts/pkg/policy"
	"github.com/jacobmichels/tail-sts/pkg/server"
	"github.com/jacobmichels/tail-sts/pkg/tailscale"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "tail-sts",
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
		},
		Action: func(c *cli.Context) error {
			return run(c)
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func run(c *cli.Context) error {
	ctx := c.Context

	policies, err := policy.GetPolicies(ctx, c.String("policies-dir"))
	if err != nil {
		return fmt.Errorf("failed to get policies: %w", err)
	}

	tsClient := tailscale.NewClient(c.String("ts-client-id"), c.String("ts-client-secret"), c.String("ts-token-url"))

	err = server.Start(policies, tsClient)
	if err != nil {
		return fmt.Errorf("failed to run server: %w", err)
	}

	return nil
}
