package jwks

import (
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(key *rsa.PrivateKey, issuer, subject, kid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": subject,
		"iss": issuer,
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}
