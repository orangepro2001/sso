// Package secure holds the cryptographic primitives the service needs, written
// against the standard library only: RS256 JWTs, the RSA key pair and its
// encrypted-at-rest private half, PKCE's S256 transform, HMAC signatures and
// the random strings the PHP got from Str::random/Str::uuid.
//
// The one exception is password hashing (bcrypt via golang.org/x/crypto): the
// PHP stored Laravel bcrypt hashes, and existing users must still sign in after
// the switch, so the hashes have to be read and written by the same algorithm.
package secure

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const Alg = "RS256"

// Encode signs the claims into a compact JWS. Only RS256 exists here: a token
// whose header says anything else is rejected on the way in, so there is no
// algorithm-confusion surface (DESIGN.md §6).
func Encode(claims map[string]any, privateKeyPEM, kid string) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": Alg, "kid": kid}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := marshalOrdered(claims)
	if err != nil {
		return "", err
	}

	signingInput := B64(headerJSON) + "." + B64(payloadJSON)

	key, err := ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signingInput + "." + B64(signature), nil
}

// Decode verifies the signature against the published key and returns the
// claims. The header's alg is checked first, exactly as Jwt::decode does.
func Decode(token, publicKeyPEM string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}

	headerJSON, err := UnB64(parts[0])
	if err != nil {
		return nil, errors.New("malformed token")
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("malformed token")
	}
	if alg, _ := header["alg"].(string); alg != Alg {
		return nil, errors.New("unsupported algorithm")
	}

	key, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return nil, errors.New("invalid verification key")
	}

	signature, err := UnB64(parts[2])
	if err != nil {
		return nil, errors.New("malformed token")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("bad signature")
	}

	payloadJSON, err := UnB64(parts[1])
	if err != nil {
		return nil, errors.New("malformed payload")
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, errors.New("malformed payload")
	}
	return claims, nil
}

// HeaderKid reads the kid without verifying anything, which is how the service
// finds out which published key to verify with (TokenService::decodeUnverified).
func HeaderKid(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := UnB64(parts[0])
	if err != nil {
		return ""
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return ""
	}
	kid, _ := header["kid"].(string)
	return kid
}

// JWK is one public key in the shape the discovery document publishes.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// PublicJWK derives the modulus and exponent from a PEM public key. The
// exponent is always AQAB (65537), which is what the PHP published too.
func PublicJWK(publicKeyPEM, kid, alg string) (JWK, bool) {
	key, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return JWK{}, false
	}
	n := B64(key.N.Bytes())
	if alg == "" {
		alg = Alg
	}
	return JWK{Kty: "RSA", Use: "sig", Alg: alg, Kid: kid, N: n, E: "AQAB"}, true
}

// GenerateKeyPair makes the RS256 key pair. 3072 bits is the same size the PHP
// generated (SigningKeyService::generate).
func GenerateKeyPair(bits int) (privatePEM, publicPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", fmt.Errorf("generate rsa key: %w", err)
	}
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	return string(pem.EncodeToMemory(privBlock)), string(pem.EncodeToMemory(pubBlock)), nil
}

func ParsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("invalid signing key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid signing key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid signing key")
	}
	return key, nil
}

func ParsePublicKey(pemText string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("invalid verification key")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("invalid verification key")
}

// B64 is base64url without padding (Jwt::b64).
func B64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func UnB64(s string) ([]byte, error) {
	if data, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	// Tolerate padded input from other implementations.
	return base64.URLEncoding.DecodeString(strings.TrimRight(s, "=") + strings.Repeat("=", (4-len(s)%4)%4))
}

// marshalOrdered encodes claims as JSON. encoding/json sorts object keys, which
// is legal JSON and verifies the same; only the byte order differs from PHP's
// insertion order, and nothing reads the raw payload.
func marshalOrdered(claims map[string]any) ([]byte, error) { return json.Marshal(claims) }
