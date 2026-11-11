package secure

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword is Laravel's Hash::make: bcrypt with the framework's default
// cost. The rounds are configurable only for tests (BCRYPT_ROUNDS), the same
// way phpunit.xml sets them to 4 to keep the suite quick.
func HashPassword(plain string, rounds int) (string, error) {
	if rounds < bcrypt.MinCost || rounds > bcrypt.MaxCost {
		rounds = 12
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), rounds)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword verifies a Laravel bcrypt hash. It deliberately does not accept
// other Laravel hashers (argon2) — production used bcrypt ($2y$), and reading a
// hash the platform cannot verify is better reported than silently denied.
func CheckPassword(hash, plain string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// RandomString is Str::random: lower/upper case letters and digits.
func RandomString(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return RandomFrom(alphabet, n)
}

// RandomFrom draws uniformly from a caller-supplied alphabet.
func RandomFrom(alphabet string, n int) string {
	if n <= 0 || alphabet == "" {
		return ""
	}
	out := make([]byte, n)
	max := byte(len(alphabet))
	// Rejection sampling keeps the distribution flat; the alphabet sizes used
	// here (62, 54) never divide 256 evenly.
	buf := make([]byte, n*2)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("secure: no randomness: %v", err))
	}
	i, j := 0, 0
	for i < n {
		if j >= len(buf) {
			if _, err := rand.Read(buf); err != nil {
				panic(fmt.Sprintf("secure: no randomness: %v", err))
			}
			j = 0
		}
		b := buf[j]
		j++
		if b >= byte(256-(256%int(max))) {
			continue
		}
		out[i] = alphabet[int(b)%len(alphabet)]
		i++
	}
	return string(out)
}

// UUID is Str::uuid: a version 4 identifier, used for jti and family_id.
func UUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("secure: no randomness: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}

// Token returns one of the service's prefixed secrets ("sso_c_…", "sso_r_…",
// "sso_pw_…") with 48 characters of randomness, like Str::random(48).
func Token(prefix string) string { return prefix + RandomString(48) }

// SHA256Hex is what the PHP wrote whenever it stored a token: only the digest,
// so a database dump is never a pile of live credentials.
func SHA256Hex(value string) string {
	sum := SHA256Sum([]byte(value))
	return hex.EncodeToString(sum)
}

// PKCEChallenge is the S256 transform (RFC 7636 §4.2).
func PKCEChallenge(verifier string) string { return B64(SHA256Sum([]byte(verifier))) }

// NormalizeUsername is strtolower(trim(...)) for the identifiers people type.
func NormalizeUsername(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

// ConstantTimeEquals compares two secrets without leaking where they differ.
func ConstantTimeEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
