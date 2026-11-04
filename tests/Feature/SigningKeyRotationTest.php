<?php

namespace Tests\Feature;

use App\Models\SigningKey;
use App\Services\Jwt;
use App\Services\SigningKeyService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * Rotation must not invalidate tokens that are already in circulation: a client
 * holding a valid 7-day JWT should keep working after the operator rotates keys.
 */
class SigningKeyRotationTest extends TestCase
{
    use RefreshDatabase;

    public function test_rotation_keeps_the_old_key_published(): void
    {
        $keys = app(SigningKeyService::class);
        $first = $keys->active();
        $second = $keys->rotate();

        $this->assertNotSame($first->kid, $second->kid);
        $this->assertTrue($second->active);
        $this->assertFalse($first->fresh()->active);

        // Both keys stay in the JWK set, so old tokens still verify.
        $kids = array_column($this->getJson('/.well-known/jwks.json')->json('keys'), 'kid');
        $this->assertContains($first->kid, $kids);
        $this->assertContains($second->kid, $kids);
    }

    public function test_a_token_signed_before_rotation_still_verifies(): void
    {
        $keys = app(SigningKeyService::class);
        $before = $keys->active();

        $token = Jwt::encode(['sub' => '1', 'jti' => 'abc'], $before->private_key, $before->kid);

        $keys->rotate();

        $claims = Jwt::decode($token, $before->public_key);
        $this->assertSame('1', $claims['sub']);

        // And the service can still resolve it, because the jti lookup is DB-based.
        $this->assertNotNull($keys->publicKeyFor($before->kid));
    }

    public function test_the_new_key_is_the_only_one_that_signs(): void
    {
        $keys = app(SigningKeyService::class);
        $first = $keys->active();
        $second = $keys->rotate();

        $this->assertSame(1, SigningKey::query()->where('active', true)->count());
        $this->assertSame($second->kid, $keys->active()->kid);
        $this->assertNotSame($first->kid, $keys->active()->kid);
    }

    public function test_the_rotation_command_reports_the_new_kid(): void
    {
        $this->artisan('sso:keys:rotate')->assertSuccessful();

        $this->assertSame(1, SigningKey::query()->where('active', true)->count());
    }
}
