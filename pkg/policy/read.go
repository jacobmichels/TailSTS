package policy

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

func ReadFromDir(dir string) (PolicyList, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var policies PolicyList
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		policy, err := readFromFile(dir + "/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read policy: %w", err)
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

func readFromFile(filename string) (Policy, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return Policy{}, fmt.Errorf("failed to read file: %w", err)
	}

	var policy Policy
	err = toml.Unmarshal(contents, &policy)
	if err != nil {
		return Policy{}, fmt.Errorf("failed to unmarshal TOML: %w", err)
	}

	return policy, nil
}
