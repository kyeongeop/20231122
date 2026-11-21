package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrMalformed   = errors.New("jwt: malformed token")
	ErrBadSig      = errors.New("jwt: signature mismatch")
	ErrAlgRejected = errors.New("jwt: algorithm rejected by policy")
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	// Ext is an opaque, unknown extension block carried in the header.
	// Its semantics are defined by the extension plugin under test.
	Ext json.RawMessage `json:"x-ext,omitempty"`
}

type Token struct {
	Raw       string
	Header    Header
	Claims    map[string]any
	Signing   string // header.payload portion that is signed
	Signature []byte
}

func b64enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64dec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Parse splits and decodes a compact JWT without verifying anything.
func Parse(raw string) (*Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformed, len(parts))
	}
	hdrRaw, err := b64dec(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	var hdr Header
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header json: %v", ErrMalformed, err)
	}
	plRaw, err := b64dec(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	var claims map[string]any
	if err := json.Unmarshal(plRaw, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload json: %v", ErrMalformed, err)
	}
	sig, err := b64dec(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}
	return &Token{
		Raw:       raw,
		Header:    hdr,
		Claims:    claims,
		Signing:   parts[0] + "." + parts[1],
		Signature: sig,
	}, nil
}

// SignHS256 builds an HS256 token; used by the harness to forge tokens.
func SignHS256(claims map[string]any, secret []byte, ext json.RawMessage) (string, error) {
	return sign("HS256", claims, ext, func(signing string) ([]byte, error) {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(signing))
		return m.Sum(nil), nil
	})
}

// SignRS256 builds a legitimate RS256 token.
func SignRS256(claims map[string]any, key *rsa.PrivateKey, ext json.RawMessage) (string, error) {
	return sign("RS256", claims, ext, func(signing string) ([]byte, error) {
		d := sha256.Sum256([]byte(signing))
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	})
}

func sign(alg string, claims map[string]any, ext json.RawMessage, f func(string) ([]byte, error)) (string, error) {
	hdr := Header{Alg: alg, Typ: "JWT", Ext: ext}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64enc(hb) + "." + b64enc(pb)
	sig, err := f(signing)
	if err != nil {
		return "", err
	}
	return signing + "." + b64enc(sig), nil
}
