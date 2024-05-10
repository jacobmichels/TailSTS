package main

import (
	"context"
	"fmt"

	"github.com/jacobmichels/tail-sts/pkg/policy"
)

func main() {
	ctx := context.Background()

	policies := getPolicies(ctx)
	fmt.Printf("Loaded %d policies\n", len(policies))
}

func getPolicies(ctx context.Context) []policy.Policy {
	policies, err := policy.ReadPoliciesFromDir("policies")
	if err != nil {
		panic(err)
	}

	for _, policy := range policies {
		err := policy.LoadJwks(ctx)
		if err != nil {
			panic(err)
		}
	}

	return policies
}
