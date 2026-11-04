<?php

namespace Tests\Feature;

use App\Models\OauthClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * An unauthenticated /oauth/authorize must survive the login round trip: the
 * client's parameters are parked in the session and replayed after sign-in, so a
 * user who was logged out never ends up back at a client error page.
 */
class PendingAuthorizeResumeTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        // The parked request lives in the session and must survive the login round
        // trip, which the in-memory array driver does not emulate. Use the real
        // driver (the sessions table exists) for this file only.
        config(['session.driver' => 'database']);
    }

    /**
     * Strip the origin so the URL can be replayed against the test client.
     */
    private function appPath(string $url): string
    {
        $path = parse_url($url, PHP_URL_PATH) ?: '/';
        $query = parse_url($url, PHP_URL_QUERY);

        return $path.($query === null ? '' : '?'.$query);
    }

    private function pkce(): array
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return [$verifier, $challenge];
    }

    public function test_an_anonymous_authorize_is_parked_and_resumed_after_login(): void
    {
        $client = OauthClient::factory()->create();
        $user = User::factory()->create([
            'username' => 'resumeuser',
            'password' => 'resume-password-1',
        ]);
        [$verifier, $challenge] = $this->pkce();

        // 1. Anonymous: redirected to the login form, request parked.
        $first = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'state' => 'carry-me',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));

        $first->assertRedirect(route('login'));
        $this->assertNotNull(session('oauth.pending'));

        // 2. Sign in: the controller sends the browser back to /oauth/authorize.
        $login = $this->post('/login', [
            'username' => 'resumeuser',
            'password' => 'resume-password-1',
        ]);

        $login->assertRedirect();
        $this->assertStringContainsString('/oauth/authorize', (string) $login->headers->get('Location'));
        $this->assertStringContainsString('carry-me', (string) $login->headers->get('Location'));
        $this->assertStringContainsString('code_challenge='.$challenge, (string) $login->headers->get('Location'));

        // 3. Replaying that URL now yields a code for the signed-in user.
        $resume = $this->appPath((string) $login->headers->get('Location'));
        $granted = $this->get($resume);

        $granted->assertRedirect();
        $location = (string) $granted->headers->get('Location');
        $this->assertStringStartsWith('https://client.example/callback?', $location);

        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame('carry-me', $query['state']);
        $this->assertNotEmpty($query['code']);

        // 4. And the code is redeemable with the original verifier.
        $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->client_id,
            'code' => $query['code'],
            'redirect_uri' => 'https://client.example/callback',
            'code_verifier' => $verifier,
        ])->assertOk();
    }
}
