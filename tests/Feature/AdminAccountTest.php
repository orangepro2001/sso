<?php

namespace Tests\Feature;

use App\Models\Admin;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class AdminAccountTest extends TestCase
{
    use RefreshDatabase;

    private function signIn(string $password = 'boss-password-1'): Admin
    {
        $admin = Admin::factory()->create(['email' => 'boss@example.test', 'password' => $password]);
        $this->post('/admin/login', ['email' => 'boss@example.test', 'password' => $password])
            ->assertRedirect(route('admin.dashboard'));

        return $admin;
    }

    public function test_an_admin_can_change_their_own_password(): void
    {
        $admin = $this->signIn();

        $this->put('/admin/account/password', [
            'current_password' => 'boss-password-1',
            'password' => 'the-new-password-2',
            'password_confirmation' => 'the-new-password-2',
        ])->assertRedirect(route('admin.account'));

        $this->assertTrue(Hash::check('the-new-password-2', $admin->fresh()->password));
        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.password_changed']);
    }

    public function test_the_wrong_current_password_is_refused(): void
    {
        $admin = $this->signIn();

        $this->put('/admin/account/password', [
            'current_password' => 'not-my-password',
            'password' => 'the-new-password-2',
            'password_confirmation' => 'the-new-password-2',
        ])->assertSessionHasErrors('current_password');

        $this->assertTrue(Hash::check('boss-password-1', $admin->fresh()->password));
        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.password_change.failed']);
    }

    public function test_confirmation_must_match_and_the_password_must_be_long(): void
    {
        $this->signIn();

        $this->put('/admin/account/password', [
            'current_password' => 'boss-password-1',
            'password' => 'the-new-password-2',
            'password_confirmation' => 'something-else-entirely',
        ])->assertSessionHasErrors('password');

        $this->put('/admin/account/password', [
            'current_password' => 'boss-password-1',
            'password' => 'short',
            'password_confirmation' => 'short',
        ])->assertSessionHasErrors('password');
    }

    public function test_the_account_page_needs_a_session(): void
    {
        $this->get('/admin/account')->assertRedirect(route('admin.login'));
    }

    public function test_the_cli_command_resets_a_password(): void
    {
        $admin = Admin::factory()->create(['email' => 'boss@example.test']);

        $this->artisan('sso:admin-password', [
            'email' => 'boss@example.test',
            '--password' => 'from-the-command-1',
        ])->assertSuccessful();

        $this->assertTrue(Hash::check('from-the-command-1', $admin->fresh()->password));
        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.cli.password_reset']);
    }

    public function test_the_cli_command_lists_admins_and_rejects_unknown_emails(): void
    {
        Admin::factory()->create(['email' => 'boss@example.test']);

        $this->artisan('sso:admin-password')->assertSuccessful();
        $this->artisan('sso:admin-password', ['email' => 'ghost@example.test'])->assertFailed();
        $this->artisan('sso:admin-password', [
            'email' => 'boss@example.test', '--password' => 'short',
        ])->assertFailed();
    }

    public function test_the_cli_command_can_disable_an_admin(): void
    {
        $admin = Admin::factory()->create(['email' => 'boss@example.test']);

        $this->artisan('sso:admin-password', ['email' => 'boss@example.test', '--disable' => true])
            ->assertSuccessful();

        $this->assertFalse($admin->fresh()->active);
    }
}
