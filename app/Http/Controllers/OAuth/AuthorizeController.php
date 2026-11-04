<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Models\OauthAuthCode;
use App\Models\OauthClient;
use App\Services\AuditLogger;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

/**
 * GET /oauth/authorize — authorization code flow with mandatory PKCE (S256).
 *
 * There is no interactive consent screen: clients are registered by an
 * administrator, so the client registration itself is the consent. Users just
 * authenticate, which keeps the flow usable for internal tooling.
 */
class AuthorizeController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function __invoke(Request $request): JsonResponse|RedirectResponse
    {
        $clientId = (string) $request->query('client_id', '');
        $client = OauthClient::query()->where('client_id', $clientId)->where('active', true)->first();

        if ($client === null) {
            return $this->fail($request, 'invalid_request', 'Unknown or inactive client_id');
        }

        $redirectUri = (string) $request->query('redirect_uri', '');
        if ($redirectUri === '' ? count($client->redirect_uris ?? []) === 1 : false) {
            $redirectUri = $client->redirect_uris[0];
        }

        if (! $client->hasRedirectUri($redirectUri)) {
            return $this->fail($request, 'invalid_request', 'redirect_uri is not registered for this client');
        }

        if ((string) $request->query('response_type', '') !== 'code') {
            return $this->redirectError($redirectUri, 'unsupported_response_type', 'Only response_type=code is supported', $request);
        }

        [$challenge, $method] = $this->pkce($request, $redirectUri);

        $requestedScopes = $this->scopes($request);
        $scopes = $client->grantedScopes($requestedScopes);
        if ($scopes === []) {
            return $this->redirectError($redirectUri, 'invalid_scope', 'No requestable scope is allowed for this client', $request);
        }

        $user = Auth::guard('web')->user();
        if ($user === null || ! $user->isActive()) {
            // Keep the request around; the login form posts back and we resume here.
            $request->session()->put('oauth.pending', $request->only([
                'client_id', 'redirect_uri', 'scope', 'state', 'code_challenge', 'code_challenge_method', 'nonce',
            ]));

            return redirect()->guest(route('login'));
        }

        $plain = 'sso_c_'.Str::random(48);
        OauthAuthCode::create([
            'code_hash' => hash('sha256', $plain),
            'client_id' => $client->client_id,
            'user_id' => $user->id,
            'redirect_uri' => $redirectUri,
            'scopes' => $scopes,
            'code_challenge' => $challenge,
            'code_challenge_method' => $method,
            'expires_at' => now()->addSeconds((int) config('sso.auth_code_ttl', 300)),
        ]);

        $this->audit->log('authorize.granted', 'user', $user->id, 'client', $client->client_id, [
            'scopes' => $scopes,
        ], $request);

        return $this->redirectWith($redirectUri, [
            'code' => $plain,
            'state' => $request->query('state'),
        ]);
    }

    /**
     * @return array{0: string|null, 1: string|null}
     */
    private function pkce(Request $request, string $redirectUri): array
    {
        $challenge = $request->query('code_challenge');
        $method = strtoupper((string) $request->query('code_challenge_method', 'S256'));

        if (! is_string($challenge) || $challenge === '') {
            return [null, null];
        }

        if (! in_array($method, ['S256', 'PLAIN'], true)) {
            return [null, null];
        }

        return [$challenge, $method];
    }

    /**
     * @return string[]
     */
    private function scopes(Request $request): array
    {
        $raw = trim((string) $request->query('scope', ''));

        return $raw === '' ? ['openid', 'profile'] : array_values(array_unique(preg_split('/\s+/', $raw) ?: []));
    }

    private function fail(Request $request, string $error, string $description): JsonResponse
    {
        // Nothing may be echoed to an unvalidated redirect_uri.
        if ($request->expectsJson()) {
            return response()->json(['error' => $error, 'error_description' => $description], 400);
        }

        return response()->json(['error' => $error, 'error_description' => $description], 400);
    }

    private function redirectError(string $redirectUri, string $error, string $description, Request $request): RedirectResponse
    {
        $this->audit->log('authorize.denied', null, null, null, null, [
            'error' => $error, 'description' => $description, 'client_id' => $request->query('client_id'),
        ], $request);

        return $this->redirectWith($redirectUri, [
            'error' => $error,
            'error_description' => $description,
            'state' => $request->query('state'),
        ]);
    }

    /**
     * @param  array<string, mixed>  $params
     */
    private function redirectWith(string $uri, array $params): RedirectResponse
    {
        $params = array_filter($params, fn ($v) => $v !== null && $v !== '');
        $separator = str_contains($uri, '?') ? '&' : '?';

        return redirect()->away($uri.$separator.http_build_query($params));
    }
}
