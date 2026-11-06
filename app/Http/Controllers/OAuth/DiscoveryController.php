<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Services\Jwt;
use App\Services\SigningKeyService;
use Illuminate\Http\JsonResponse;

/**
 * RFC 8414 / OIDC discovery + JWKS. Both are public and cacheable for a while.
 */
class DiscoveryController extends Controller
{
    public function __construct(private readonly SigningKeyService $keys) {}

    public function openidConfiguration(): JsonResponse
    {
        $issuer = rtrim((string) config('sso.issuer'), '/');

        $document = [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'userinfo_endpoint' => $issuer.'/oauth/userinfo',
            'introspection_endpoint' => $issuer.'/oauth/introspect',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'jwks_uri' => $issuer.'/.well-known/jwks.json',
            'scopes_supported' => array_keys((array) config('sso.scopes', [])),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token', 'client_credentials'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic', 'none'],
            'code_challenge_methods_supported' => ['S256'],
            'claims_supported' => ['sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'scope', 'name', 'preferred_username', 'picture', 'role'],
            'service_documentation' => $issuer.'/../docs/DESIGN.md',
        ];

        return response()->json($document)
            ->header('Cache-Control', 'public, max-age=600');
    }

    public function jwks(): JsonResponse
    {
        // Touch the active key first: on a brand new database the key pair is
        // generated lazily, and the JWKS must never be empty while tokens exist.
        $this->keys->active();

        return response()->json(['keys' => Jwt::jwks($this->keys->publishable())])
            ->header('Cache-Control', 'public, max-age=600');
    }
}
