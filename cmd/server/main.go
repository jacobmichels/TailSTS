package main

import (
	"context"
	"os"

	"github.com/jacobmichels/tail-sts/pkg/policy"
	"github.com/jacobmichels/tail-sts/pkg/server"
	"github.com/jacobmichels/tail-sts/pkg/tailscale"
)

func main() {
	ctx := context.Background()

	policies, err := policy.GetPolicies(ctx, "policies")
	if err != nil {
		panic(err)
	}

	tsClient := tailscale.NewClient(os.Getenv("TS_CLIENT_ID"), os.Getenv("TS_CLIENT_SECRET"))

	err = server.Start(policies, tsClient)
	if err != nil {
		panic(err)
	}
}
