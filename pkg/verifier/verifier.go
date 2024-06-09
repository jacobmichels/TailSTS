package verifier

import "github.com/MicahParks/keyfunc/v3"

type Verifier interface {
	Verify(token, alg string, kf keyfunc.Keyfunc) error
}
