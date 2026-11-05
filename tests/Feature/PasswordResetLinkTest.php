<?php

namespace Tests\Feature;

use App\Models\AccessToken;
use App\Models\Admin;
use App\Models\RefreshToken;
use App\Models\User;
use App\Models\UserPasswordReset;
use App\Services\PasswordResetService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

/**
 * One-time reset links: the administrator mints one, hands it over out of band, and
 * the user sets their own password. Single use, expiring, superseded by any newer
 * link -- it is a bearer token for an account, so it has to behave like one.
 */
class PasswordResetLinkTest extends TestCase
{
    use RefreshDatabase;

    private function signInAdmin(): Admin
    {
        $admin = Admin::factory()->create(['email' => 'boss@example.test', 'password' => 'boss-password-1']);
        $this->post('/admin/login', ['email' => 'boss@example.test', 'password' => 'boss-password-1']);

        return $admin;
    }

    private function issueToken(User $user): string
    {
        [$plain] = app(PasswordResetService::class)->issue($user);

        return $plain;
    }

    public function test_an_admin_creates_a_link_and_sees_it_once(): void
    {
        $user = User::factory()->create(['username' => 'linkuser']);
        $this->signInAdmin();

        $response = $this->post("/admin/users/{$user->id}/reset-link");

        $response->assertRedirect(route('admin.users.edit', $user));
        $url = session('reset_url');
        $this->assertIsString($url);
        $this->assertStringContainsString('/password/reset/sso_pw_', $url);

        // Stored hashed, never in the clear.
        $this->assertDatabaseMissing('user_password_resets', ['token_hash' => $url]);
        $this->assertSame(1, UserPasswordReset::query()->where('user_id', $user->id)->count());

        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.user.reset_link_created']);
    }

    public function test_the_link_opens_a_password_form(): void
    {
        $user = User::factory()->create(['username' => 'formuser']);
        $token = $this->issueToken($user);

        $this->get("/password/reset/{$token}")
            ->assertOk()
            ->assertSee('Set a new password')
            ->assertSee('formuser');
    }

    public function test_the_user_sets_a_password_and_can_sign_in(): void
    {
        $user = User::factory()->create(['username' => 'resetter', 'password' => 'forgotten-password-1']);
        $token = $this->issueToken($user);

        $this->post("/password/reset/{$token}", [
            'password' => 'chosen-by-the-user-42',
            'password_confirmation' => 'chosen-by-the-user-42',
        ])->assertRedirect(route('login'));

        $this->assertTrue(Hash::check('chosen-by-the-user-42', $user->fresh()->password));

        $this->post('/login', ['username' => 'resetter', 'password' => 'chosen-by-the-user-42'])
            ->assertRedirect();
        $this->assertAuthenticatedAs($user, 'web');

        $this->assertDatabaseHas('audit_logs', ['event' => 'user.password_reset.completed']);
    }

    public function test_a_link_works_only_once(): void
    {
        $user = User::factory()->create(['username' => 'once']);
        $token = $this->issueToken($user);

        $this->post("/password/reset/{$token}", [
            'password' => 'first-new-password-1',
            'password_confirmation' => 'first-new-password-1',
        ])->assertRedirect();

        $this->get("/password/reset/{$token}")->assertOk()->assertSee('This link cannot be used');

        $this->post("/password/reset/{$token}", [
            'password' => 'second-new-password-2',
            'password_confirmation' => 'second-new-password-2',
        ])->assertOk()->assertSee('This link cannot be used');

        $this->assertTrue(Hash::check('first-new-password-1', $user->fresh()->password));
    }

    public function test_an_expired_link_is_refused(): void
    {
        $user = User::factory()->create(['username' => 'stale']);
        $token = $this->issueToken($user);

        UserPasswordReset::query()->where('user_id', $user->id)->update(['expires_at' => now()->subMinute()]);

        $this->get("/password/reset/{$token}")->assertOk()->assertSee('This link cannot be used');
    }

    public function test_an_unknown_link_is_refused_without_leaking_anything(): void
    {
        $this->get('/password/reset/sso_pw_totally-made-up')
            ->assertOk()
            ->assertSee('This link cannot be used');

        $this->assertDatabaseHas('audit_logs', ['event' => 'user.password_reset.rejected']);
    }

    public function test_a_new_link_supersedes_the_previous_one(): void
    {
        $user = User::factory()->create(['username' => 'superseded']);
        $old = $this->issueToken($user);
        $new = $this->issueToken($user);

        $this->get("/password/reset/{$old}")->assertOk()->assertSee('This link cannot be used');
        $this->get("/password/reset/{$new}")->assertOk()->assertSee('Set a new password');
    }

    public function test_a_short_password_is_rejected_and_the_link_stays_usable(): void
    {
        $user = User::factory()->create(['username' => 'shorty']);
        $token = $this->issueToken($user);

        $this->post("/password/reset/{$token}", [
            'password' => 'too-short',
            'password_confirmation' => 'too-short',
        ])->assertSessionHasErrors('password');

        $this->get("/password/reset/{$token}")->assertOk()->assertSee('Set a new password');
    }

    public function test_a_reset_revokes_every_credential_the_user_holds(): void
    {
        $user = User::factory()->create(['username' => 'revoked']);

        $token = AccessToken::create([
            'kind' => AccessToken::KIND_JWT,
            'jti' => 'jti-revoke-test',
            'subject_type' => AccessToken::SUBJECT_USER,
            'user_id' => $user->id,
            'scopes' => ['openid'],
            'expires_at' => now()->addDay(),
        ]);

        $refresh = RefreshToken::create([
            'token_hash' => hash('sha256', 'r1'),
            'family_id' => 'fam-1',
            'user_id' => $user->id,
            'client_id' => 'c1',
            'scopes' => ['openid'],
            'expires_at' => now()->addDay(),
        ]);

        $link = $this->issueToken($user);

        $this->post("/password/reset/{$link}", [
            'password' => 'brand-new-password-1',
            'password_confirmation' => 'brand-new-password-1',
        ])->assertRedirect();

        $this->assertNotNull($token->fresh()->revoked_at);
        $this->assertNotNull($refresh->fresh()->revoked_at);
    }

    public function test_replacing_the_password_from_the_console_also_revokes_credentials(): void
    {
        $user = User::factory()->create(['username' => 'consolechange']);

        $token = AccessToken::create([
            'kind' => AccessToken::KIND_JWT,
            'jti' => 'jti-console-test',
            'subject_type' => AccessToken::SUBJECT_USER,
            'user_id' => $user->id,
            'scopes' => ['openid'],
            'expires_at' => now()->addDay(),
        ]);

        $this->signInAdmin();

        $this->post("/admin/users/{$user->id}/password", ['password' => 'console-chosen-1'])
            ->assertRedirect();

        $this->assertNotNull($token->fresh()->revoked_at);
    }

    public function test_the_link_points_at_the_public_issuer_not_the_container(): void
    {
        $user = User::factory()->create(['username' => 'issuercheck']);
        $this->signInAdmin();

        $this->post("/admin/users/{$user->id}/reset-link");

        $url = (string) session('reset_url');
        $this->assertStringStartsWith('https://sso.test/sso/password/reset/', $url);
        $this->assertStringNotContainsString('127.0.0.1', $url);
    }
}
