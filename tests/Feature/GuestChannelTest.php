<?php

namespace Tests\Feature;

use App\Models\GuestDevice;
use App\Models\OauthClient;
use App\Models\User;
use App\Services\GuestService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class GuestChannelTest extends TestCase
{
    use RefreshDatabase;

    private function signature(string $deviceId): string
    {
        return app(GuestService::class)->sign($deviceId);
    }

    public function test_a_validly_signed_device_is_enrolled_and_gets_an_eternal_token(): void
    {
        $deviceId = 'lab-host-07';
        $response = $this->postJson('/oauth/guest', [
            'device_id' => $deviceId,
            'algo' => 'hmac-sha256',
            'signature' => $this->signature($deviceId),
        ]);

        $response->assertOk()
            ->assertJsonPath('token_type', 'Bearer')
            ->assertJsonPath('device_id', $deviceId)
            ->assertJsonPath('newly_enrolled', true)
            ->assertJsonPath('signature_valid', true)
            ->assertJsonPath('scope', 'db:read')
            ->assertJsonPath('expires_in', null);

        $this->assertNotEmpty($response->json('access_token'));

        $device = GuestDevice::query()->where('device_id', $deviceId)->firstOrFail();
        $this->assertSame(GuestDevice::STATUS_ACTIVE, $device->status);
        $this->assertSame(1, $device->request_count);
        $this->assertNull($device->tokens()->first()->expires_at);
    }

    public function test_a_suspicious_device_is_still_approved(): void
    {
        // Wrong signature: policy says let it in and review afterwards.
        $response = $this->postJson('/oauth/guest', [
            'device_id' => 'unknown-box',
            'signature' => str_repeat('f', 64),
        ]);

        $response->assertOk()
            ->assertJsonPath('signature_valid', false)
            ->assertJsonPath('newly_enrolled', true);

        $this->assertNotEmpty($response->json('access_token'));
        $this->assertDatabaseHas('audit_logs', ['event' => 'guest.enrolled']);
    }

    public function test_a_device_without_a_signature_is_still_approved(): void
    {
        $response = $this->postJson('/oauth/guest', ['device_id' => 'bare-host']);

        $response->assertOk()->assertJsonPath('signature_valid', false);
        $this->assertNotEmpty($response->json('access_token'));
    }

    public function test_the_second_call_reuses_the_device_row(): void
    {
        $deviceId = 'repeat-host';
        $this->postJson('/oauth/guest', ['device_id' => $deviceId, 'signature' => $this->signature($deviceId)])->assertOk();
        $this->postJson('/oauth/guest', ['device_id' => $deviceId, 'signature' => $this->signature($deviceId)])
            ->assertOk()
            ->assertJsonPath('newly_enrolled', false);

        $this->assertSame(1, GuestDevice::query()->where('device_id', $deviceId)->count());
        $this->assertSame(2, GuestDevice::query()->where('device_id', $deviceId)->value('request_count'));
    }

    public function test_a_blacklisted_device_is_refused(): void
    {
        $deviceId = 'rogue-host';
        $first = $this->postJson('/oauth/guest', ['device_id' => $deviceId, 'signature' => $this->signature($deviceId)]);
        $first->assertOk();

        $device = GuestDevice::query()->where('device_id', $deviceId)->firstOrFail();
        $adminToken = \App\Models\Admin::factory()->create();

        $this->actingAs($adminToken, 'admin')
            ->post("/admin/devices/{$device->id}/block", ['reason' => 'test'])
            ->assertRedirect();

        $this->postJson('/oauth/guest', ['device_id' => $deviceId, 'signature' => $this->signature($deviceId)])
            ->assertStatus(403)
            ->assertJsonPath('error', 'access_denied');

        // And the token it already holds stops introspecting.
        $client = OauthClient::factory()->confidential('top-secret-1')->create();
        $this->postJson('/oauth/introspect', [
            'client_id' => $client->client_id,
            'client_secret' => 'top-secret-1',
            'token' => $first->json('access_token'),
        ])->assertOk()->assertJsonPath('active', false);
    }

    public function test_device_id_is_required_and_bounded(): void
    {
        $this->postJson('/oauth/guest', [])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
        $this->postJson('/oauth/guest', ['device_id' => str_repeat('x', 200)])->assertStatus(400);
        $this->postJson('/oauth/guest', ['device_id' => '   '])->assertStatus(400);
    }

    public function test_a_guest_token_resolves_through_userinfo(): void
    {
        $deviceId = 'userinfo-host';
        $token = $this->postJson('/oauth/guest', [
            'device_id' => $deviceId,
            'signature' => $this->signature($deviceId),
        ])->json('access_token');

        $this->withHeader('Authorization', 'Bearer '.$token)
            ->getJson('/oauth/userinfo')
            ->assertOk()
            ->assertJsonPath('subject_type', 'guest')
            ->assertJsonPath('device_id', $deviceId);
    }

    public function test_the_signature_is_hmac_sha256_of_the_prefixed_device_id(): void
    {
        $expected = hash_hmac('sha256', "sso-guest-v1\ndev-1", (string) config('sso.guest.secret'));
        $this->assertSame($expected, $this->signature('dev-1'));
    }
}
