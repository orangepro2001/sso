package secure

import (
	"strings"
	"testing"
)

// The PHP stored Laravel bcrypt hashes. Go's bcrypt reads the $2y$ prefix
// password_hash() writes, which is the one thing that lets existing people sign
// in after the switch; this test pins it.
func TestBcryptReadsPHPHashes(t *testing.T) {
	// password_hash('password', PASSWORD_DEFAULT) at the default cost, as the
	// PHP documentation prints it.
	hash := "$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi"

	if !CheckPassword(hash, "password") {
		t.Fatal("a $2y$ hash from PHP must verify")
	}
	if CheckPassword(hash, "wrong") {
		t.Fatal("a wrong password verified")
	}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("generated-by-the-console", 4)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if !CheckPassword(hash, "generated-by-the-console") {
		t.Fatal("the new hash does not verify")
	}
}

func TestPKCEChallengeMatchesRFC7636(t *testing.T) {
	// RFC 7636 Appendix B: the verifier/challenge pair every S256 test uses.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if got := PKCEChallenge(verifier); got != want {
		t.Fatalf("challenge = %s, want %s", got, want)
	}
}

func TestJWTVerifiesAndRejectsTampering(t *testing.T) {
	privatePEM, publicPEM, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	token, err := Encode(map[string]any{"sub": "42", "scope": "openid"}, privatePEM, "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("not a compact JWS: %s", token)
	}

	claims, err := Decode(token, publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "42" {
		t.Fatalf("sub = %v", claims["sub"])
	}
	if HeaderKid(token) != "kid-1" {
		t.Fatalf("kid = %q", HeaderKid(token))
	}

	// A forged payload with the original signature is refused.
	parts := strings.Split(token, ".")
	forged := parts[0] + "." + B64([]byte(`{"sub":"1"}`)) + "." + parts[2]
	if _, err := Decode(forged, publicPEM); err == nil {
		t.Fatal("a tampered payload verified")
	}

	// "alg: none" is refused outright, which is the whole algorithm-confusion
	// surface (DESIGN.md §6).
	unsigned := B64([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + B64([]byte(`{"sub":"7"}`)) + "."
	if _, err := Decode(unsigned, publicPEM); err == nil {
		t.Fatal("an unsigned token verified")
	}
}

func TestPrivateKeyEnvelopeNeedsTheRightAppKey(t *testing.T) {
	privatePEM, publicPEM, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := EncryptPrivateKey("base64:the-real-key", privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "v1:") || strings.Contains(sealed, "PRIVATE") {
		t.Fatalf("the envelope leaks the key: %.40s", sealed)
	}

	opened, err := DecryptPrivateKey("base64:the-real-key", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if opened != privatePEM {
		t.Fatal("the decrypted key differs")
	}

	if _, err := DecryptPrivateKey("base64:another-key", sealed); err == nil {
		t.Fatal("a different APP_KEY decrypted the private key")
	}
	if _, err := DecryptPrivateKey("base64:the-real-key", privatePEM); err == nil {
		t.Fatal("an unencrypted value was accepted")
	}
	_ = publicPEM
}

func TestJWKCarriesTheModulusAndNoPrivatePart(t *testing.T) {
	_, publicPEM, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk, ok := PublicJWK(publicPEM, "kid-1", Alg)
	if !ok {
		t.Fatal("could not build a JWK")
	}
	if jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.E != "AQAB" || jwk.N == "" {
		t.Fatalf("unexpected JWK: %+v", jwk)
	}
	if strings.Contains(jwk.N, "=") || strings.ContainsAny(jwk.N, "+/") {
		t.Fatalf("the modulus is not base64url: %s", jwk.N)
	}
}
