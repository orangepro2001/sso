<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Models\OauthAuthCode;
use App\Models\OauthClient;
use App\Models\User;
use App\Services\AuditLogger;
use App\Services\ClientAuthenticator;
use App\Services\OAuthException;
use App\Services\TokenService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * POST /oauth/token — authorization_code, refresh_token and client_credentials.
 */
class TokenController extends Controller
{
    public function __construct(
        private readonly ClientAuthenticator $clients,
        private readonly TokenService $tokens,
        private readonly AuditLogger $audit,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        try {
            $client = $this->clients->authenticate($request);
            $grantType = (string) $request->input('grant_type', '');

            $payload = match ($grantType) {
                'authorization_code' => $this->authorizationCode($request, $client->client_id),
                'refresh_token' => $this->refreshToken($request, $client),
                'client_credentials' => $this->clientCredentials($request, $client),
                default => throw OAuthException::unsupportedGrantType(
                    'grant_type must be authorization_code, refresh_token or client_credentials'
                ),
            };
        } catch (OAuthException $e) {
            $this->audit->log('token.error', null, null, null, null, [
                'error' => $e->errorCode, 'description' => $e->getMessage(), 'grant_type' => $request->input('grant_type'),
            ], $request);

            return $e->toJsonResponse();
        }

        return response()->json($payload)->withHeaders([
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function authorizationCode(Request $request, string $clientId): array
    {
        $plain = (string) $request->input('code', '');
        if ($plain === '') {
            throw OAuthException::invalidRequest('code is required');
        }

        $code = OauthAuthCode::query()->where('code_hash', hash('sha256', $plain))->first();
        if ($code === null) {
            throw OAuthException::invalidGrant('Unknown authorization code');
        }

        if ($code->client_id !== $clientId) {
            throw OAuthException::invalidGrant('Authorization code was issued to another client');
        }

        if ($code->consumed_at !== null) {
            throw OAuthException::invalidGrant('Authorization code already used');
        }

        if ($code->expires_at->isPast()) {
            throw OAuthException::invalidGrant('Authorization code expired');
        }

        $redirectUri = (string) $request->input('redirect_uri', '');
        if ($redirectUri !== '' && $redirectUri !== $code->redirect_uri) {
            throw OAuthException::invalidGrant('redirect_uri mismatch');
        }

        if ($code->code_challenge !== null) {
            $this->verifyPkce($request, $code);
        }

        $user = User::query()->find($code->user_id);
        if ($user === null || ! $user->isActive()) {
            throw OAuthException::invalidGrant('Account is not active');
        }

        $code->forceFill(['consumed_at' => now()])->save();

        return $this->tokens->issueForUser($user, $clientId, $code->scopes, $request);
    }

    private function verifyPkce(Request $request, OauthAuthCode $code): void
    {
        $verifier = (string) $request->input('code_verifier', '');
        if ($verifier === '') {
            throw OAuthException::invalidGrant('code_verifier is required for this authorization code');
        }

        $computed = $code->code_challenge_method === 'PLAIN'
            ? $verifier
            : rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        if (! hash_equals((string) $code->code_challenge, $computed)) {
            throw OAuthException::invalidGrant('code_verifier does not match the code_challenge');
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function refreshToken(Request $request, OauthClient $client): array
    {
        $plain = (string) $request->input('refresh_token', '');
        if ($plain === '') {
            throw OAuthException::invalidRequest('refresh_token is required');
        }

        return $this->tokens->refresh($plain, $client, $request);
    }

    /**
     * @return array<string, mixed>
     */
    private function clientCredentials(Request $request, OauthClient $client): array
    {
        if ($client->isPublic()) {
            throw OAuthException::unauthorizedClient('Public clients cannot use client_credentials');
        }

        $requested = trim((string) $request->input('scope', ''));
        $scopes = $requested === ''
            ? $client->grantedScopes(['db:read'])
            : $client->grantedScopes(preg_split('/\s+/', $requested) ?: []);

        if ($scopes === []) {
            throw OAuthException::invalidScope('None of the requested scopes is allowed for this client');
        }

        return $this->tokens->issueForClient($client, $scopes, $request);
    }
}
