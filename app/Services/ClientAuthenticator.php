<?php

namespace App\Services;

use App\Models\OauthClient;
use Illuminate\Http\Request;

/**
 * Client authentication for the token / introspection / revocation endpoints.
 *
 * Supports client_secret_basic, client_secret_post and "none" (public clients,
 * which are forced through PKCE at the authorize step).
 */
class ClientAuthenticator
{
    public function authenticate(Request $request): OauthClient
    {
        [$clientId, $secret] = $this->credentials($request);

        if ($clientId === null || $clientId === '') {
            throw OAuthException::invalidClient('client_id is required');
        }

        $client = OauthClient::query()->where('client_id', $clientId)->first();
        if ($client === null || ! $client->active) {
            throw OAuthException::invalidClient('Unknown or inactive client');
        }

        if (! $client->verifySecret($secret)) {
            throw OAuthException::invalidClient('Client authentication failed');
        }

        return $client;
    }

    /**
     * @return array{0: string|null, 1: string|null}
     */
    private function credentials(Request $request): array
    {
        $header = $request->header('Authorization');
        if (is_string($header) && str_starts_with($header, 'Basic ')) {
            $decoded = base64_decode(substr($header, 6), true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                [$id, $secret] = explode(':', $decoded, 2);

                // RFC 6749 §2.3.1: both parts are form-encoded before base64.
                return [urldecode($id), urldecode($secret)];
            }
        }

        $id = $request->input('client_id');
        $secret = $request->input('client_secret');

        return [
            is_string($id) ? $id : null,
            is_string($secret) ? $secret : null,
        ];
    }
}
