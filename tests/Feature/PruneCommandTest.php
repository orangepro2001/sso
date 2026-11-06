<?php

namespace Tests\Feature;

use App\Models\AccessToken;
use App\Models\AuditLog;
use App\Models\OauthAuthCode;
use App\Models\RefreshToken;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * Pruning deletes only rows that can no longer authenticate anything.
 */
class PruneCommandTest extends TestCase
{
    use RefreshDatabase;

    private function userToken(User $user, array $overrides = []): AccessToken
    {
        return AccessToken::create($overrides + [
            'kind' => AccessToken::KIND_JWT,
            'jti' => (string) Str::uuid(),
            'subject_type' => AccessToken::SUBJECT_USER,
            'user_id' => $user->id,
            'scopes' => ['openid'],
            'expires_at' => now()->addDay(),
        ]);
    }

    public function test_revoked_and_expired_tokens_go(): void
    {
        $user = User::factory()->create();
        $revoked = $this->userToken($user, ['revoked_at' => now()]);
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

    public function test_a_live_token_is_never_touched(): void
    {
        $live = $this->userToken(User::factory()->create());

        $this->artisan('sso:prune')->assertSuccessful();

        $this->assertNotNull($live->fresh());
    }

    public function test_dry_run_deletes_nothing(): void
    {
        $user = User::factory()->create();
        $this->userToken($user, ['revoked_at' => now()]);
        $this->userToken($user, ['expires_at' => now()->subDay()]);

        $this->artisan('sso:prune', ['--dry-run' => true])->assertSuccessful();

        $this->assertSame(2, AccessToken::query()->where('user_id', $user->id)->count());
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
