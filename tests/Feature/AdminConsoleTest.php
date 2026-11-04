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
            'email' => 'new@example.test',
            'password' => 'a-very-good-password',
        ])->assertRedirect(route('admin.users.index'));

        $user = User::query()->where('email', 'new@example.test')->firstOrFail();
        $this->assertSame(User::STATUS_ACTIVE, $user->status);

        $this->post('/login', ['email' => 'new@example.test', 'password' => 'a-very-good-password'])
            ->assertRedirect();
        $this->assertAuthenticatedAs($user, 'web');
    }

    public function test_duplicate_emails_are_rejected(): void
    {
        User::factory()->create(['email' => 'taken@example.test']);
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'Dup',
            'email' => 'taken@example.test',
            'password' => 'a-very-good-password',
        ])->assertSessionHasErrors('email');
    }

    public function test_a_disabled_user_cannot_sign_in(): void
    {
        User::factory()->disabled()->create([
            'email' => 'off@example.test',
            'password' => 'a-very-good-password',
        ]);

        $this->post('/login', ['email' => 'off@example.test', 'password' => 'a-very-good-password'])
            ->assertSessionHasErrors('email');
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
        User::factory()->create(['email' => 'kept@example.test', 'password' => 'a-very-good-password']);

        $this->post('/login', [
            'email' => 'kept@example.test',
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
            'email' => 'audited@example.test',
            'password' => 'a-very-good-password',
        ]);

        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.user.created']);
        $this->get('/admin/audit')->assertOk();
    }
}
