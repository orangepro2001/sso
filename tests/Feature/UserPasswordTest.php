<?php

namespace Tests\Feature;

use App\Models\Admin;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

/**
 * A password is shown exactly once, right after it is set. The form never
 * pre-fills one, because a value rendered into a page can belong to an older
 * render (refresh, back button) and then differs from what is stored -- which is
 * how an "initial password" that cannot log in happened.
 */
class UserPasswordTest extends TestCase
{
    use RefreshDatabase;

    private function signIn(): Admin
    {
        $admin = Admin::factory()->create(['email' => 'boss@example.test', 'password' => 'boss-password-1']);
        $this->post('/admin/login', ['email' => 'boss@example.test', 'password' => 'boss-password-1']);

        return $admin;
    }

    public function test_the_create_form_does_not_prefill_a_password(): void
    {
        $this->signIn();

        $response = $this->get('/admin/users/create')->assertOk();

        $response->assertSee('leave blank to generate one');
        // No value attribute on the password input.
        $this->assertDoesNotMatchRegularExpression('/id="password"[^>]*value="[^"]+"/', $response->getContent());
    }

    public function test_a_blank_password_is_generated_and_shown_once(): void
    {
        $this->signIn();

        $response = $this->post('/admin/users', [
            'name' => 'Generated Person',
            'username' => 'generated',
            'password' => '',
        ]);

        $response->assertRedirect(route('admin.users.index'));
        $generated = session('generated_password');
        $this->assertIsArray($generated);
        $this->assertArrayHasKey('generated', $generated);

        $plain = $generated['generated'];
        $this->assertGreaterThanOrEqual(12, strlen($plain));

        // The shown value is the stored one: it signs in.
        $user = User::query()->where('username', 'generated')->firstOrFail();
        $this->assertTrue(Hash::check($plain, $user->password));

        $this->post('/login', ['username' => 'generated', 'password' => $plain])->assertRedirect();
        $this->assertAuthenticatedAs($user, 'web');
    }

    public function test_a_typed_password_is_used_as_is(): void
    {
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'Typed Person',
            'username' => 'typed',
            'password' => 'chosen-password-42',
        ])->assertRedirect();

        $user = User::query()->where('username', 'typed')->firstOrFail();
        $this->assertTrue(Hash::check('chosen-password-42', $user->password));

        $this->post('/login', ['username' => 'typed', 'password' => 'chosen-password-42'])->assertRedirect();
        $this->assertAuthenticatedAs($user, 'web');
    }

    public function test_a_short_typed_password_is_rejected(): void
    {
        $this->signIn();

        $this->post('/admin/users', [
            'name' => 'Short',
            'username' => 'shortpw',
            'password' => 'too-short',
        ])->assertSessionHasErrors('password');

        $this->assertNull(User::query()->where('username', 'shortpw')->first());
    }

    public function test_the_edit_form_does_not_prefill_a_password(): void
    {
        $user = User::factory()->create(['username' => 'editable']);
        $this->signIn();

        $response = $this->get("/admin/users/{$user->id}/edit")->assertOk();

        $this->assertDoesNotMatchRegularExpression('/id="new-password"[^>]*value="[^"]+"/', $response->getContent());
        $response->assertSee('Only this button changes the password', false);
    }

    public function test_replacing_the_password_shows_the_new_one_once(): void
    {
        $user = User::factory()->create(['username' => 'rotated']);
        $this->signIn();

        $response = $this->post("/admin/users/{$user->id}/password", ['password' => '']);
        $response->assertRedirect(route('admin.users.edit', $user));

        $generated = session('generated_password');
        $this->assertArrayHasKey('rotated', $generated);
        $this->assertTrue(Hash::check($generated['rotated'], $user->fresh()->password));
    }

    public function test_the_cli_command_resets_a_user_password(): void
    {
        $user = User::factory()->create(['username' => 'cliuser']);

        $this->artisan('sso:user-password', [
            'username' => 'cliuser',
            '--password' => 'from-the-command-1',
        ])->assertSuccessful();

        $this->assertTrue(Hash::check('from-the-command-1', $user->fresh()->password));
        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.cli.user_password_reset']);
    }

    public function test_the_cli_command_lists_users_and_rejects_unknown_names(): void
    {
        User::factory()->create(['username' => 'listed']);

        $this->artisan('sso:user-password')->assertSuccessful();
        $this->artisan('sso:user-password', ['username' => 'ghost'])->assertFailed();
        $this->artisan('sso:user-password', ['username' => 'listed', '--password' => 'short'])->assertFailed();
    }
}
