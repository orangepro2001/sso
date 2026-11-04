<?php

namespace Tests\Feature;

use App\Models\Admin;
use App\Models\OauthClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AdminConsoleTest extends TestCase
{
    use RefreshDatabase;

    private function admin(): Admin
    {
        return Admin::factory()->create(['email' => 'boss@example.test', 'password' => 'boss-password-1']);
    }

    private function signIn(): Admin
    {
        $admin = $this->admin();
        $this->post('/admin/login', ['email' => 'boss@example.test', 'password' => 'boss-password-1'])
            ->assertRedirect(route('admin.dashboard'));

        return $admin;
    }

    public function test_the_console_is_closed_to_anonymous_visitors(): void
    {
        $this->get('/admin')->assertRedirect(route('admin.login'));
        $this->get('/admin/users')->assertRedirect(route('admin.login'));
        $this->get('/admin/devices')->assertRedirect(route('admin.login'));
    }

    public function test_the_user_sign_in_page_points_administrators_elsewhere(): void
    {
        // The two identity spaces have separate forms; a person holding an admin
        // account must be told so instead of being left with "credentials do not
        // match" (that is exactly what happened in practice).
        $this->get('/login')
            ->assertOk()
            ->assertSee('Administrator?')
            ->assertSee(route('admin.login'));
    }

    public function test_an_admin_account_does_not_sign_in_on_the_user_page(): void
    {
        $this->admin();

        $this->post('/login', ['username' => 'boss@example.test', 'password' => 'boss-password-1'])
            ->assertSessionHasErrors('username');

        $this->assertGuest('web');
        $this->assertGuest('admin');
    }

    public function test_a_user_account_does_not_sign_in_on_the_console_page(): void
    {
        User::factory()->create(['username' => 'plainuser', 'password' => 'a-very-good-password']);

        // A user account is not an admin account, even with the right password.
        $this->post('/admin/login', ['email' => 'plainuser', 'password' => 'a-very-good-password'])
            ->assertSessionHasErrors('email');

        $this->assertGuest('admin');
    }

    public function test_the_home_page_links_to_both_sign_in_pages(): void
    {
        $this->get('/')
            ->assertOk()
            ->assertSee('Administrator console')
            ->assertSee('User sign-in');
    }

    public function test_there_is_no_registration_route(): void
    {
        $this->get('/register')->assertNotFound();
        $this->post('/register', [])->assertNotFound();
    }

    public function test_an_admin_can_create_a_user_and_the_user_can_sign_in(): void
    {
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'New Person',
            'username' => 'newperson',
            'password' => 'a-very-good-password',
        ])->assertRedirect(route('admin.users.index'));

        $user = User::query()->where('username', 'newperson')->firstOrFail();
        $this->assertSame(User::STATUS_ACTIVE, $user->status);
        // Three fields, no e-mail anywhere.
        $this->assertArrayNotHasKey('email', $user->getAttributes());

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
        ])->assertRedirect();

        $this->assertDatabaseHas('users', ['username' => 'mixed.case-1']);

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

    public function test_remember_me_works_for_an_admin(): void
    {
        // The admins table used to lack remember_token, so ticking this box made
        // the login itself fail with an undefined-column error.
        $this->admin();

        $this->post('/admin/login', [
            'email' => 'boss@example.test',
            'password' => 'boss-password-1',
            'remember' => '1',
        ])->assertRedirect(route('admin.dashboard'));

        $this->assertAuthenticated('admin');
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

    public function test_the_bootstrap_command_creates_the_first_admin_only_once(): void
    {
        $this->artisan('sso:bootstrap')->assertSuccessful();

        $this->assertDatabaseHas('admins', ['email' => 'root@example.test']);

        $this->artisan('sso:bootstrap')->assertSuccessful();
        $this->assertSame(1, Admin::query()->count());
    }

    public function test_the_audit_log_records_admin_actions(): void
    {
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'Audited',
            'username' => 'audited',
            'password' => 'a-very-good-password',
        ]);

        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.user.created']);
        $this->get('/admin/audit')->assertOk();
    }
}
