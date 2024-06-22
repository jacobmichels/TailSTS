package server

import (
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type JWKSVerifier struct{}

var _ OIDCTokenVerifier = (*JWKSVerifier)(nil)

func (v JWKSVerifier) Verify(token, alg string, kf keyfunc.Keyfunc) error {
	_, err := jwt.Parse(string(token), kf.Keyfunc, jwt.WithValidMethods([]string{alg}))
	return err
}
