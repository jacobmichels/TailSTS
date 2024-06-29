package policy

import (
	"errors"
	"net/url"
)

func ValidatePolicies(policies PolicyList) error {
	var result error
	for _, policy := range policies {
		err := ValidatePolicy(policy)
		result = errors.Join(result, err)
	}

	return nil
}

func ValidatePolicy(policy Policy) error {
	var result error
	err := validateAlgorithm(policy.Algorithm)
	result = errors.Join(result, err)

	err = validateScopes(policy.AllowedScopes)
	result = errors.Join(result, err)

	err = validateIssuer(policy.Issuer)
	result = errors.Join(result, err)

	err = validateJWKSUrl(policy.JwksURL)
	result = errors.Join(result, err)

	return result
}

func validateAlgorithm(alg string) error {
	switch alg {
	case "RS256":
		return nil
	default:
		return errors.New("unsupported algorithm")
	}
}

func validateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return errors.New("no scopes")
	}

	return nil
}

func validateIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("no issuer")
	}

	return nil
}

func validateJWKSUrl(jwksURL string) error {
	if jwksURL == "" {
		return errors.New("no JWKS URL")
	}

	_, err := url.Parse(jwksURL)
	if err != nil {
		return errors.New("unparsable JWKS URL")
	}

	return nil
}
