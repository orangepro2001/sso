package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// SHA256Sum is used wherever the PHP wrote hash('sha256', …).
func SHA256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// DeriveAppKey turns APP_KEY into the AES-256 key that protects the signing
// key's private half.
//
// The derivation is a domain-separated SHA-256 of the raw APP_KEY string, so
// the rule is the same for a Laravel-style "base64:…" value and for a plain
// passphrase, and rotating APP_KEY (or importing a dump with a different one)
// fails loudly on decrypt instead of producing half-working state.
//
// DESIGN.md §6: the root filesystem is read-only and no key material ships in
// the image, so the pair lives in the database — but a database clone must not
// be immediately a signing oracle.
func DeriveAppKey(appKey string) [32]byte {
	return sha256.Sum256([]byte("sso/signing-key/v1\x00" + appKey))
}

const keyCipherPrefix = "v1:"

// EncryptPrivateKey is AES-256-GCM; the stored value is "v1:" + base64(nonce|ct|tag).
func EncryptPrivateKey(appKey, privatePEM string) (string, error) {
	block, err := aes.NewCipher(appKeyBytes(appKey))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(privatePEM), nil)
	return keyCipherPrefix + base64.StdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// DecryptPrivateKey reverses EncryptPrivateKey. Anything that is not the "v1:"
// envelope is refused rather than guessed at.
func DecryptPrivateKey(appKey, stored string) (string, error) {
	if !strings.HasPrefix(stored, keyCipherPrefix) {
		return "", errors.New("signing key is not in the encrypted envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, keyCipherPrefix))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(appKeyBytes(appKey))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("signing key is truncated")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("could not decrypt the signing key: is APP_KEY the one the database was written with?")
	}
	return string(plain), nil
}

func appKeyBytes(appKey string) []byte {
	key := DeriveAppKey(appKey)
	return key[:]
}
