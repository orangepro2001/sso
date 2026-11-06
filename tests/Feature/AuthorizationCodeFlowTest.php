<?php

namespace Tests\Feature;

use App\Models\OauthClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthorizationCodeFlowTest extends TestCase
{
    use RefreshDatabase;

    private function client(array $overrides = []): OauthClient
    {
        return OauthClient::factory()->create($overrides);
    }

    private function pkce(): array
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return [$verifier, $challenge];
    }

    private function login(): User
    {
        $user = User::factory()->create([
            'username' => 'plainuser',
            'password' => 'user-password-1',
        ]);

        $this->post('/login', ['username' => 'plainuser', 'password' => 'user-password-1'])
            ->assertRedirect();

        return $user;
    }

    public function test_the_full_code_flow_yields_a_seven_day_token_and_a_refresh_token(): void
    {
        $client = $this->client();
        [$verifier, $challenge] = $this->pkce();
        $user = $this->login();

        $authorize = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid profile offline_access',
            'state' => 'xyz',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]));

        $authorize->assertRedirect();
        $location = $authorize->headers->get('Location');
        $this->assertStringStartsWith('https://client.example/callback?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame('xyz', $query['state']);
        $this->assertNotEmpty($query['code']);

        $token = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->client_id,
            'code' => $query['code'],
            'redirect_uri' => 'https://client.example/callback',
            'code_verifier' => $verifier,
        ]);

        $token->assertOk()
            ->assertJsonPath('token_type', 'Bearer')
            ->assertJsonPath('scope', 'openid profile offline_access');

        $this->assertSame(604800, $token->json('expires_in'));
        $this->assertNotEmpty($token->json('refresh_token'));
        $this->assertNotEmpty($token->json('id_token'));

        // The authorization code is single use.
        $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->client_id,
            'code' => $query['code'],
            'redirect_uri' => 'https://client.example/callback',
            'code_verifier' => $verifier,
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    }

    public function test_a_wrong_pkce_verifier_is_rejected(): void
    {
        $client = $this->client();
        [, $challenge] = $this->pkce();
        $this->login();

        $location = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->headers->get('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->client_id,
            'code' => $query['code'],
            'code_verifier' => 'not-the-verifier',
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    }

    public function test_a_public_client_without_pkce_is_refused(): void
    {
        // Without a secret there is nothing else binding the code to the client,
        // so PKCE is mandatory (RFC 9700).
        $client = $this->client();
        $this->login();

        $response = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
        ]));

        $response->assertRedirect();
        $location = (string) $response->headers->get('Location');
        $this->assertStringContainsString('error=invalid_request', $location);
        $this->assertStringNotContainsString('code=', $location);
    }

    public function test_a_confidential_client_may_omit_pkce(): void
    {
        $client = OauthClient::factory()->confidential('very-secret-1')->create();
        $this->login();

        $location = (string) $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
        ]))->headers->get('Location');

        $this->assertStringContainsString('code=', $location);
    }

    public function test_the_plain_pkce_method_is_refused(): void
    {
        $client = $this->client();
        $this->login();

        $location = (string) $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => 'abc',
            'code_challenge_method' => 'plain',
        ]))->headers->get('Location');

        $this->assertStringContainsString('error=invalid_request', $location);
    }

    public function test_an_unregistered_redirect_uri_is_refused(): void
    {
        $client = $this->client();

        $this->getJson('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://evil.example/callback',
            'scope' => 'openid',
        ]))->assertStatus(400)->assertJsonPath('error', 'invalid_request');
    }

    public function test_refresh_rotates_and_reuse_kills_the_family(): void
    {
        $client = $this->client();
        [$verifier, $challenge] = $this->pkce();
        $this->login();

        $location = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid offline_access',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->headers->get('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        $first = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->client_id,
            'code' => $query['code'],
            'code_verifier' => $verifier,
        ])->assertOk();

        $refresh = $first->json('refresh_token');
        $this->assertNotEmpty($refresh);

        // First refresh succeeds and hands out a new refresh token.
        $rotated = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->client_id,
            'refresh_token' => $refresh,
        ])->assertOk();

        $this->assertNotSame($refresh, $rotated->json('refresh_token'));

        // Replaying the old one is treated as theft: the whole family dies.
        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->client_id,
            'refresh_token' => $refresh,
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

        $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->client_id,
            'refresh_token' => $rotated->json('refresh_token'),
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

        $this->assertDatabaseHas('audit_logs', ['event' => 'token.reuse_detected']);
    }

    public function test_public_clients_cannot_use_client_credentials(): void
    {
        $client = $this->client();

        $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $client->client_id,
        ])->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
    }

    public function test_confidential_clients_use_client_credentials_with_basic_auth(): void
    {
        $client = OauthClient::factory()->confidential('very-secret-1')->create();

        $response = $this->withHeader('Authorization', 'Basic '.base64_encode($client->client_id.':very-secret-1'))
            ->postJson('/oauth/token', ['grant_type' => 'client_credentials', 'scope' => 'db:read']);

        $response->assertOk()->assertJsonPath('scope', 'db:read');
        $this->assertSame(604800, $response->json('expires_in'));
    }

    public function test_a_bad_client_secret_is_rejected(): void
    {
        $client = OauthClient::factory()->confidential('very-secret-1')->create();

        $this->postJson('/oauth/token', [
            'grant_type' => 'client_credentials',
            'client_id' => $client->client_id,
            'client_secret' => 'wrong',
        ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
    }

    public function test_a_disabled_user_token_stops_resolving(): void
    {
        $client = OauthClient::factory()->confidential('very-secret-1')->create();
        $user = $this->login();

        [$verifier, $challenge] = $this->pkce();

        $location = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->headers->get('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        $access = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->client_id,
            'client_secret' => 'very-secret-1',
            'code' => $query['code'],
            'code_verifier' => $verifier,
        ])->assertOk()->json('access_token');

        $this->withHeader('Authorization', 'Bearer '.$access)->getJson('/oauth/userinfo')->assertOk();

        $user->forceFill(['status' => User::STATUS_DISABLED])->save();

        $this->withHeader('Authorization', 'Bearer '.$access)->getJson('/oauth/userinfo')->assertStatus(401);
    }

    public function test_userinfo_carries_the_role(): void
    {
        $client = OauthClient::factory()->confidential('very-secret-1')->create();
        $user = $this->login();

        [$verifier, $challenge] = $this->pkce();

        $location = $this->get('/oauth/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $client->client_id,
            'redirect_uri' => 'https://client.example/callback',
            'scope' => 'openid profile',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->headers->get('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        $access = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->client_id,
            'client_secret' => 'very-secret-1',
            'code' => $query['code'],
            'code_verifier' => $verifier,
        ])->assertOk()->json('access_token');

        $user->forceFill(['role' => User::ROLE_SUPER_ADMIN])->save();

        $this->withHeader('Authorization', 'Bearer '.$access)->getJson('/oauth/userinfo')
            ->assertOk()
            ->assertJsonPath('role', 'super_admin');
    }
}
