<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Services\AuditLogger;
use App\Services\ClientAuthenticator;
use App\Services\OAuthException;
use App\Services\TokenService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * POST /oauth/introspect (RFC 7662) and POST /oauth/revoke (RFC 7009).
 *
 * Introspection requires client authentication so that a token cannot be probed
 * (and therefore validated) by anyone who happens to hold it.
 */
class IntrospectController extends Controller
{
    public function __construct(
        private readonly ClientAuthenticator $clients,
        private readonly TokenService $tokens,
        private readonly AuditLogger $audit,
    ) {}

    public function introspect(Request $request): JsonResponse
    {
        try {
            $client = $this->clients->authenticate($request);
        } catch (OAuthException $e) {
            return $e->toJsonResponse();
        }

        $token = $request->input('token');
        $body = is_string($token) && $token !== '' ? $this->tokens->introspect($token) : null;

        if ($body === null) {
            return response()->json(['active' => false])->header('Cache-Control', 'no-store');
        }

        $this->audit->log('token.introspected', 'client', $client->client_id, 'token', $body['jti'] ?? null, [
            'subject_type' => $body['subject_type'] ?? null,
        ], $request);

        return response()->json($body)->header('Cache-Control', 'no-store');
    }

    public function revoke(Request $request): JsonResponse
    {
        try {
            $this->clients->authenticate($request);
        } catch (OAuthException $e) {
            return $e->toJsonResponse();
        }

        $token = $request->input('token');
        if (is_string($token) && $token !== '') {
            $this->tokens->revoke($token);
        }

        // RFC 7009 §2.2: always 200, even for unknown tokens.
        return response()->json([], 200)->header('Cache-Control', 'no-store');
    }
}
