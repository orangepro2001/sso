<?php

namespace Tests\Feature;

use App\Services\Jwt;
use App\Services\SigningKeyService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DiscoveryTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_discovery_document_describes_the_sso_mount_point(): void
    {
        $this->getJson('/.well-known/openid-configuration')
            ->assertOk()
            ->assertJsonPath('issuer', 'https://sso.test/sso')
            ->assertJsonPath('token_endpoint', 'https://sso.test/sso/oauth/token')
            ->assertJsonPath('guest_endpoint', 'https://sso.test/sso/oauth/guest')
            ->assertJsonPath('jwks_uri', 'https://sso.test/sso/.well-known/jwks.json')
            ->assertJsonPath('code_challenge_methods_supported', ['S256']);
    }

    public function test_the_jwks_exposes_an_rsa_key_and_nothing_private(): void
    {
        $response = $this->getJson('/.well-known/jwks.json')->assertOk();
        $keys = $response->json('keys');

        $this->assertNotEmpty($keys);
        $this->assertSame('RSA', $keys[0]['kty']);
        $this->assertSame('sig', $keys[0]['use']);
        $this->assertSame('RS256', $keys[0]['alg']);
        $this->assertArrayNotHasKey('private_key', $keys[0]);
        $this->assertArrayNotHasKey('d', $keys[0]);
    }

    public function test_a_signed_token_round_trips_and_a_tampered_one_does_not(): void
    {
        $keys = app(SigningKeyService::class);
        $key = $keys->active();

        $token = Jwt::encode(['sub' => '42', 'iss' => 'x'], $key->private_key, $key->kid);
        $claims = Jwt::decode($token, $key->public_key);

        $this->assertSame('42', $claims['sub']);

        $tampered = substr($token, 0, -3).'abc';
        $this->expectException(\RuntimeException::class);
        Jwt::decode($tampered, $key->public_key);
    }

    public function test_the_health_endpoint_answers(): void
    {
        $this->getJson('/healthz')->assertOk()->assertJsonPath('status', 'ok');
    }
}
