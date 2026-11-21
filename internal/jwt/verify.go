package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// Verifier decides whether a token is accepted. The two implementations
// below are the vulnerable (legacy) and fixed (current) behaviors that the
// reproduction pipeline snapshots and compares.
type Verifier interface {
	Name() string
	Verify(tok *Token) error
}

// LegacyVerifier is the vulnerable implementation: it trusts the token's
// own "alg" header and, for HS256, verifies with the RSA *public* key bytes
// as the HMAC secret. This is the classic RS256->HS256 confusion.
type LegacyVerifier struct {
	PublicKey *rsa.PublicKey
}

func (v *LegacyVerifier) Name() string { return "legacy-v1" }

func (v *LegacyVerifier) Verify(tok *Token) error {
	switch tok.Header.Alg {
	case "RS256":
		d := sha256.Sum256([]byte(tok.Signing))
		if err := rsa.VerifyPKCS1v15(v.PublicKey, crypto.SHA256, d[:], tok.Signature); err != nil {
			return ErrBadSig
		}
		return nil
	case "HS256":
		// Vulnerable: public key material reused as HMAC secret.
		secret := PublicKeyDER(v.PublicKey)
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(tok.Signing))
		if !hmac.Equal(m.Sum(nil), tok.Signature) {
			return ErrBadSig
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrAlgRejected, tok.Header.Alg)
	}
}

// FixedVerifier pins the expected algorithm and never confuses key types.
type FixedVerifier struct {
	PublicKey *rsa.PublicKey
}

func (v *FixedVerifier) Name() string { return "fixed-v2" }

func (v *FixedVerifier) Verify(tok *Token) error {
	if tok.Header.Alg != "RS256" {
		return fmt.Errorf("%w: %s", ErrAlgRejected, tok.Header.Alg)
	}
	d := sha256.Sum256([]byte(tok.Signing))
	if err := rsa.VerifyPKCS1v15(v.PublicKey, crypto.SHA256, d[:], tok.Signature); err != nil {
		return ErrBadSig
	}
	return nil
}

// PublicKeyDER returns the DER encoding of the public key. The attacker
// knows this value (it is public), which is exactly why the confusion works.
func PublicKeyDER(pub *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
