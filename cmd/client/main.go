package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "TailSTS Client",
		Usage: "Convenience CLI Client for TailSTS",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server",
				Usage:   "TailSTS server URL",
				Aliases: []string{"s", "url", "u", "addr", "a"},
				EnvVars: []string{"TAILSTS_SERVER"},
				Value:   "http://localhost:8080",
			},
			&cli.StringFlag{
				Name:     "token",
				Usage:    "OIDC token to exchange for a Tailscale token",
				Aliases:  []string{"t"},
				EnvVars:  []string{"OIDC_TOKEN"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "scopes",
				Usage:   "Comma-separated list of scopes to request",
				Aliases: []string{"scope"},
				EnvVars: []string{"SCOPES"},
				Value:   "acls",
			},
		},
		Action: func(c *cli.Context) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			return run(c, *logger)
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

type Response struct {
	AccessToken string `json:"token"`
}

func run(c *cli.Context, logger slog.Logger) error {
	logger.Info("Running TailSTS Client")

	server := c.String("server")
	token := c.String("token")
	scopes := c.String("scopes")

	body := `{"scopes": ["` + scopes + `"]}`

	req, err := http.NewRequest("POST", server, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed: %s", resp.Status)
	}

	logger.Info("Request successful", "status", resp.Status)

	accessToken := Response{}
	err = json.NewDecoder(resp.Body).Decode(&accessToken)
	if err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	logger.Info("Response", "accessToken", accessToken.AccessToken)

	return nil
}
