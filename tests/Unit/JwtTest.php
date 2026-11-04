<?php

namespace Tests\Unit;

use App\Services\Jwt;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class JwtTest extends TestCase
{
    private function keyPair(): array
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($resource, $private);
        $details = openssl_pkey_get_details($resource);

        return [$private, $details['key']];
    }

    public function test_claims_survive_an_encode_decode_round_trip(): void
    {
        [$private, $public] = $this->keyPair();

        $token = Jwt::encode(['sub' => '7', 'scope' => 'openid'], $private, 'kid-1');
        $claims = Jwt::decode($token, $public);

        $this->assertSame('7', $claims['sub']);
        $this->assertSame('openid', $claims['scope']);
        $this->assertCount(3, explode('.', $token));
    }

    public function test_a_tampered_payload_is_rejected(): void
    {
        [$private, $public] = $this->keyPair();
        $token = Jwt::encode(['sub' => '7'], $private, 'kid-1');

        [$header, , $signature] = explode('.', $token);
        $forged = $header.'.'.Jwt::b64(json_encode(['sub' => '1'])).'.'.$signature;

        $this->expectException(RuntimeException::class);
        Jwt::decode($forged, $public);
    }

    public function test_another_key_cannot_verify_the_signature(): void
    {
        [$private] = $this->keyPair();
        [, $otherPublic] = $this->keyPair();

        $token = Jwt::encode(['sub' => '7'], $private, 'kid-1');

        $this->expectException(RuntimeException::class);
        Jwt::decode($token, $otherPublic);
    }

    public function test_a_non_rs256_header_is_refused(): void
    {
        [$private, $public] = $this->keyPair();

        // "alg: none" style attack: rebuild the token by hand.
        $header = Jwt::b64(json_encode(['alg' => 'none', 'typ' => 'JWT']));
        $payload = Jwt::b64(json_encode(['sub' => '7']));
        $unsigned = $header.'.'.$payload.'.';

        $this->expectException(RuntimeException::class);
        Jwt::decode($unsigned, $public);
    }

    public function test_base64url_helpers_round_trip(): void
    {
        $raw = random_bytes(48);
        $this->assertSame($raw, Jwt::unb64(Jwt::b64($raw)));
        $this->assertStringNotContainsString('=', Jwt::b64($raw));
        $this->assertStringNotContainsString('+', Jwt::b64($raw));
    }
}
