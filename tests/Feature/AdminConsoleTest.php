<?php

namespace Tests\Feature;

use App\Models\OauthClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AdminConsoleTest extends TestCase
{
    use RefreshDatabase;

    private function signIn(): User
    {
        $admin = User::factory()->superAdmin()->create(['username' => 'boss', 'password' => 'boss']);
        $this->post('/login', ['username' => 'boss', 'password' => 'boss'])->assertRedirect();

        return $admin;
    }

    public function test_the_console_sends_anonymous_visitors_to_the_user_sign_in(): void
    {
        $this->get('/admin')->assertRedirect(route('login'));
        $this->get('/admin/users')->assertRedirect(route('login'));
    }

    public function test_an_ordinary_user_is_refused_the_console(): void
    {
        $this->actingAs(User::factory()->create(), 'web');

        $this->get('/admin')->assertForbidden();
        $this->get('/admin/users')->assertForbidden();
    }

    public function test_a_super_admin_signs_in_once_and_reaches_the_console(): void
    {
        User::factory()->superAdmin()->create(['username' => 'boss', 'password' => 'x']);

        // Visiting the console first, then signing in, comes back to the console.
        $this->get('/admin')->assertRedirect(route('login'));
        $this->post('/login', ['username' => 'boss', 'password' => 'x'])
            ->assertRedirect(route('admin.dashboard'));

        $this->get('/admin')->assertRedirect(route('admin.users.index'));
        $this->get('/admin/users')->assertOk();
        $this->get('/')->assertSee(route('admin.dashboard'));
    }

    public function test_a_disabled_super_admin_is_refused_the_console(): void
    {
        $this->actingAs(User::factory()->superAdmin()->disabled()->create(), 'web');

        $this->get('/admin')->assertForbidden();
    }

    public function test_the_old_console_sign_in_link_returns_to_the_console(): void
    {
        $this->get('/admin/login')->assertRedirect(route('login'));
        $this->assertSame(route('admin.dashboard'), session('url.intended'));
    }

    public function test_anyone_can_register_without_a_password_policy(): void
    {
        $this->get('/register')->assertOk();

        $this->post('/register', [
            'name' => '새 사람',
            'username' => 'NewOne',
            'password' => '1',
            'password_confirmation' => '1',
        ])->assertRedirect(route('home'));

        $user = User::query()->where('username', 'newone')->firstOrFail();
        $this->assertSame(User::ROLE_USER, $user->role);
        $this->assertAuthenticatedAs($user, 'web');
        $this->get('/admin')->assertForbidden();
    }

    public function test_old_invite_links_still_open_the_form(): void
    {
        $this->get('/register/some-old-code')->assertOk()->assertSee('Create account');
    }

    public function test_registration_still_rejects_duplicates_and_bad_usernames(): void
    {
        User::factory()->create(['username' => 'taken']);

        foreach (['taken', 'ab', 'has space'] as $bad) {
            $this->post('/register', [
                'name' => 'X', 'username' => $bad, 'password' => 'p', 'password_confirmation' => 'p',
            ])->assertSessionHasErrors('username');
        }
    }

    public function test_a_super_admin_can_promote_and_demote(): void
    {
        $this->signIn();
        $user = User::factory()->create(['username' => 'promoted']);

        $this->put("/admin/users/{$user->id}", [
            'name' => $user->name, 'username' => 'promoted', 'status' => User::STATUS_ACTIVE, 'role' => User::ROLE_SUPER_ADMIN,
        ])->assertRedirect(route('admin.users.index'));
        $this->assertTrue($user->fresh()->isSuperAdmin());

        $this->put("/admin/users/{$user->id}", [
            'name' => $user->name, 'username' => 'promoted', 'status' => User::STATUS_ACTIVE, 'role' => 'emperor',
        ])->assertSessionHasErrors('role');
    }

    public function test_the_role_command_sets_and_prints_a_role(): void
    {
        User::factory()->create(['username' => 'cli']);

        $this->artisan('sso:role', ['username' => 'cli', 'role' => 'super_admin'])->assertSuccessful();
        $this->assertDatabaseHas('users', ['username' => 'cli', 'role' => 'super_admin']);
        $this->artisan('sso:role', ['username' => 'cli', 'role' => 'nope'])->assertFailed();
    }

    public function test_an_admin_can_create_a_user_and_the_user_can_sign_in(): void
    {
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'New Person',
            'username' => 'newperson',
            'password' => 'a-very-good-password',
            'role' => User::ROLE_USER,
        ])->assertRedirect(route('admin.users.index'));

        $user = User::query()->where('username', 'newperson')->firstOrFail();
        $this->assertSame(User::STATUS_ACTIVE, $user->status);
        // Three fields, no e-mail anywhere.
        $this->assertArrayNotHasKey('email', $user->getAttributes());

        // Admin and user share one session now: sign the admin out first.
        auth('web')->logout();
        $this->post('/login', ['username' => 'newperson', 'password' => 'a-very-good-password'])
            ->assertRedirect();
        $this->assertAuthenticatedAs($user, 'web');
    }

    public function test_a_username_is_normalised_to_lower_case_and_sign_in_ignores_case(): void
    {
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'Case Test',
            'username' => 'MiXeD.Case-1',
            'password' => 'a-very-good-password',
            'role' => User::ROLE_USER,
        ])->assertRedirect();

        $this->assertDatabaseHas('users', ['username' => 'mixed.case-1']);

        // Admin and user share one session now: sign the admin out first.
        auth('web')->logout();
        $this->post('/login', ['username' => 'MIXED.case-1', 'password' => 'a-very-good-password'])
            ->assertRedirect();
        $this->assertAuthenticated('web');
    }

    public function test_username_format_and_uniqueness_are_enforced(): void
    {
        User::factory()->create(['username' => 'taken']);
        $this->signIn();

        // duplicate
        $this->post('/admin/users', [
            'name' => 'Dup', 'username' => 'taken', 'password' => 'a-very-good-password',
        ])->assertSessionHasErrors('username');

        // too short, illegal characters, leading punctuation
        foreach (['ab', 'has space', 'bad!char', '.leading'] as $bad) {
            $this->post('/admin/users', [
                'name' => 'Bad', 'username' => $bad, 'password' => 'a-very-good-password',
            ])->assertSessionHasErrors('username');
        }
    }

    public function test_a_user_keeps_their_username_when_uniqueness_is_ignored_on_update(): void
    {
        $user = User::factory()->create(['username' => 'stable']);
        $this->signIn();

        $this->put("/admin/users/{$user->id}", [
            'name' => 'Renamed',
            'username' => 'stable',
            'status' => User::STATUS_ACTIVE,
            'role' => User::ROLE_USER,
        ])->assertRedirect(route('admin.users.index'));

        $this->assertSame('Renamed', $user->fresh()->name);
    }

    public function test_duplicate_usernames_are_rejected(): void
    {
        User::factory()->create(['username' => 'taken']);
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'Dup',
            'username' => 'taken',
            'password' => 'a-very-good-password',
        ])->assertSessionHasErrors('username');
    }

    public function test_a_disabled_user_cannot_sign_in(): void
    {
        User::factory()->disabled()->create([
            'username' => 'off',
            'password' => 'a-very-good-password',
        ]);

        $this->post('/login', ['username' => 'off', 'password' => 'a-very-good-password'])
            ->assertSessionHasErrors('username');
        $this->assertGuest('web');
    }

    public function test_remember_me_works_for_a_user(): void
    {
        User::factory()->create(['username' => 'keptuser', 'password' => 'a-very-good-password']);

        $this->post('/login', [
            'username' => 'keptuser',
            'password' => 'a-very-good-password',
            'remember' => '1',
        ])->assertRedirect();

        $this->assertAuthenticated('web');
    }

    public function test_an_admin_can_register_a_confidential_client_and_sees_the_secret_once(): void
    {
        $this->signIn();

        $response = $this->post('/admin/clients', [
            'name' => 'Reporting service',
            'type' => 'confidential',
            'redirect_uris' => "https://report.example/cb\nhttps://report.example/cb2",
            'allowed_scopes' => ['openid', 'db:read'],
            'active' => '1',
        ]);

        $client = OauthClient::query()->firstOrFail();
        $response->assertRedirect(route('admin.clients.edit', $client));
        $response->assertSessionHas('client_secret');

        $this->assertCount(2, $client->redirect_uris);
        $this->assertSame(['openid', 'db:read'], $client->allowed_scopes);
        $this->assertNotNull($client->secret_hash);
    }

    public function test_the_bootstrap_command_creates_the_first_super_admin_only_once(): void
    {
        $this->artisan('sso:bootstrap')->assertSuccessful();

        $this->assertDatabaseHas('users', ['username' => 'root', 'role' => 'super_admin']);

        $this->artisan('sso:bootstrap')->assertSuccessful();
        $this->assertSame(1, User::query()->where('role', 'super_admin')->count());
    }

    public function test_the_audit_log_records_admin_actions(): void
    {
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'Audited',
            'username' => 'audited',
            'password' => 'a-very-good-password',
            'role' => User::ROLE_USER,
        ]);

        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.user.created']);
        $this->get('/admin/audit')->assertOk();
    }
}
