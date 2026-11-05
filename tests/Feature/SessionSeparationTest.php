<?php

namespace Tests\Feature;

use App\Models\Admin;
use App\Models\OauthClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * The console session and the SSO user session are separate cookies, so "signed in"
 * is never ambiguous: an administrator is signed in to the console and to nothing
 * else, and signing out of one does not sign out of the other.
 *
 * The cookie-name switch itself is covered in Tests\Unit\ConsoleSessionTest, which
 * can assert it without a request cycle.
 */
class SessionSeparationTest extends TestCase
{
    use RefreshDatabase;

    private function admin(): Admin
    {
        return Admin::factory()->create(['email' => 'boss@example.test', 'password' => 'boss-password-1']);
    }

    public function test_the_console_session_and_the_user_session_are_independent(): void
    {
        $admin = $this->admin();
        $user = User::factory()->create(['username' => 'person']);

        $this->actingAs($admin, 'admin')->actingAs($user, 'web');

        $this->assertAuthenticatedAs($admin, 'admin');
        $this->assertAuthenticatedAs($user, 'web');

        // Signing out of the console must not sign the user out of applications.
        $this->post('/admin/logout');

        $this->assertGuest('admin');
        $this->assertAuthenticatedAs($user, 'web');
    }

    public function test_a_console_login_does_not_authenticate_the_user_guard(): void
    {
        $this->admin();

        $this->post('/admin/login', [
            'email' => 'boss@example.test',
            'password' => 'boss-password-1',
        ])->assertRedirect(route('admin.dashboard'));

        $this->assertAuthenticated('admin');
        $this->assertGuest('web');
    }

    public function test_a_console_session_is_not_a_client_identity(): void
    {
        $admin = $this->admin();
        $client = OauthClient::factory()->create(['name' => '업무일보 work-report']);

        // Signed in to the console only.
        $this->actingAs($admin, 'admin');

        $challenge = rtrim(strtr(base64_encode(hash('sha256', 'verifier-1', true)), '+/', '-_'), '=');

        $response = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));

        // Bounced to the *user* sign-in page, naming the application, with no code.
        $response->assertRedirect();
        $location = (string) $response->headers->get('Location');
        $this->assertStringContainsString('/login', $location);
        $this->assertStringNotContainsString('code=', $location);
    }

    public function test_the_sign_in_page_names_the_requesting_application(): void
    {
        $this->get('/login?'.http_build_query(['client' => '업무일보 work-report']))
            ->assertOk()
            ->assertSee('업무일보 work-report')
            ->assertSee('console administrator accounts cannot be used by', false);
    }

    public function test_the_sign_in_page_has_no_client_banner_without_one(): void
    {
        $this->get('/login')->assertOk()->assertDontSee('wants to sign you in');
    }
}
