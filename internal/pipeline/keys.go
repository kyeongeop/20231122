package pipeline

import (
	"crypto/rsa"
	"fmt"

	"github.com/example/jwtconf/internal/jwt"
)

// verifiers builds the legacy (vulnerable) and fixed verifiers bound to the
// same RSA public key, mirroring a service before/after the patch.
func verifiers(pub any) (jwt.Verifier, jwt.Verifier, error) {
	key, ok := pub.(*rsa.PublicKey)
	if !ok || key == nil {
		return nil, nil, fmt.Errorf("pipeline: need *rsa.PublicKey, got %T", pub)
	}
	return &jwt.LegacyVerifier{PublicKey: key}, &jwt.FixedVerifier{PublicKey: key}, nil
}
