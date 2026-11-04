<?php

namespace Tests\Feature;

use App\Models\AccessToken;
use App\Models\AuditLog;
use App\Models\GuestDevice;
use App\Models\OauthAuthCode;
use App\Models\RefreshToken;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * Guest tokens never expire, so a chatty device would otherwise grow
 * access_tokens without bound. Pruning keeps the newest live token per device and
 * deletes only rows that can no longer authenticate anything.
 */
class PruneCommandTest extends TestCase
{
    use RefreshDatabase;

    private function guestToken(GuestDevice $device, array $overrides = []): AccessToken
    {
        return AccessToken::create($overrides + [
            'kind' => AccessToken::KIND_OPAQUE,
            'jti' => (string) Str::uuid(),
            'token_hash' => hash('sha256', (string) Str::uuid()),
            'subject_type' => AccessToken::SUBJECT_GUEST,
            'guest_device_id' => $device->id,
            'scopes' => ['db:read'],
            'expires_at' => null,
        ]);
    }

    private function device(string $id, array $overrides = []): GuestDevice
    {
        return GuestDevice::create($overrides + [
            'device_id' => $id,
            'status' => GuestDevice::STATUS_ACTIVE,
            'request_count' => 1,
            'first_seen_at' => now(),
            'last_seen_at' => now(),
        ]);
    }

    public function test_only_the_newest_guest_token_per_device_survives(): void
    {
        $device = $this->device('chatty');
        $old = $this->guestToken($device);
        $older = $this->guestToken($device);
        $newest = $this->guestToken($device);

        $this->artisan('sso:prune')->assertSuccessful();

        $this->assertNull($old->fresh());
        $this->assertNull($older->fresh());
        $this->assertNotNull($newest->fresh(), 'the newest live token must be kept');
    }

    public function test_revoked_and_expired_tokens_go(): void
    {
        $device = $this->device('d1');
        $revoked = $this->guestToken($device, ['revoked_at' => now()]);

        $user = User::factory()->create();
        $expired = AccessToken::create([
            'kind' => AccessToken::KIND_JWT,
            'jti' => (string) Str::uuid(),
            'subject_type' => AccessToken::SUBJECT_USER,
            'user_id' => $user->id,
            'scopes' => ['openid'],
            'expires_at' => now()->subDay(),
        ]);

        $this->artisan('sso:prune')->assertSuccessful();

        $this->assertNull($revoked->fresh());
        $this->assertNull($expired->fresh());
    }

    public function test_spent_authorization_codes_and_dead_refresh_tokens_go(): void
    {
        $user = User::factory()->create();

        $spent = OauthAuthCode::create([
            'code_hash' => hash('sha256', 'x'),
            'client_id' => 'c1',
            'user_id' => $user->id,
            'redirect_uri' => 'https://c.example/cb',
            'scopes' => ['openid'],
            'expires_at' => now()->subMinute(),
            'consumed_at' => now()->subMinute(),
        ]);

        $dead = RefreshToken::create([
            'token_hash' => hash('sha256', 'y'),
            'family_id' => 'f1',
            'user_id' => $user->id,
            'client_id' => 'c1',
            'scopes' => ['openid'],
            'expires_at' => now()->addDay(),
            'revoked_at' => now(),
        ]);

        $this->artisan('sso:prune')->assertSuccessful();

        $this->assertNull($spent->fresh());
        $this->assertNull($dead->fresh());
    }

    public function test_a_live_guest_token_is_never_touched(): void
    {
        $device = $this->device('steady');
        $live = $this->guestToken($device);

        $this->artisan('sso:prune')->assertSuccessful();

        $this->assertNotNull($live->fresh());
    }

    public function test_a_recently_seen_device_is_kept_and_an_old_one_removed(): void
    {
        $this->device('recent');
        $old = $this->device('forgotten');
        $old->forceFill(['last_seen_at' => now()->subDays(400)])->save();

        $this->artisan('sso:prune', ['--device-days' => 180])->assertSuccessful();

        $this->assertNotNull(GuestDevice::query()->where('device_id', 'recent')->first());
        $this->assertNull(GuestDevice::query()->where('device_id', 'forgotten')->first());
    }

    public function test_a_blacklisted_device_is_never_forgotten(): void
    {
        $blocked = $this->device('blocked', [
            'status' => GuestDevice::STATUS_BLACKLISTED,
            'last_seen_at' => now()->subDays(400),
        ]);

        $this->artisan('sso:prune', ['--device-days' => 30])->assertSuccessful();

        $this->assertNotNull($blocked->fresh(), 'losing a blacklist row would silently un-ban the device');
    }

    public function test_dry_run_deletes_nothing(): void
    {
        $device = $this->device('chatty');
        $this->guestToken($device);
        $this->guestToken($device);
        $this->guestToken($device);

        $this->artisan('sso:prune', ['--dry-run' => true])->assertSuccessful();

        $this->assertSame(3, AccessToken::query()->where('guest_device_id', $device->id)->count());
    }

    public function test_old_audit_entries_are_trimmed(): void
    {
        AuditLog::create(['event' => 'old', 'created_at' => now()->subDays(200)]);
        AuditLog::create(['event' => 'fresh', 'created_at' => now()]);

        $this->artisan('sso:prune', ['--audit-days' => 90])->assertSuccessful();

        $this->assertDatabaseMissing('audit_logs', ['event' => 'old']);
        $this->assertDatabaseHas('audit_logs', ['event' => 'fresh']);
    }
}
