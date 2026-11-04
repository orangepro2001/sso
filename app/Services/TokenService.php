<?php

namespace App\Services;

use App\Models\AccessToken;
use App\Models\GuestDevice;
use App\Models\OauthClient;
use App\Models\RefreshToken;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * The single place that mints, rotates, revokes and resolves tokens.
 *
 * Users get a short-ish RS256 JWT (7 days) plus a rotating refresh token so
 * clients can refresh silently. Guests get an opaque, non-expiring token stored
 * by hash, which the blacklist can kill instantly.
 */
class TokenService
{
    public function __construct(
        private readonly Jwt $jwt,
        private readonly SigningKeyService $keys,
        private readonly BlacklistService $blacklist,
        private readonly AuditLogger $audit,
    ) {}

    /**
     * Issue a user token pair (access JWT + rotating refresh token).
     *
     * @param  string[]  $scopes
     * @return array{access_token: string, token_type: string, expires_in: int, refresh_token: string|null, scope: string, id_token: string|null}
     */
    public function issueForUser(
        User $user,
        string $clientId,
        array $scopes,
        ?Request $request = null,
        ?string $refreshFamilyId = null,
    ): array {
        $request ??= request();
        [$token, $record, $expiresAt] = $this->mintJwt(
            subject: (string) $user->id,
            subjectType: AccessToken::SUBJECT_USER,
            scopes: $scopes,
            clientId: $clientId,
            user: $user,
            request: $request,
        );

        $refresh = null;
        if (in_array('offline_access', $scopes, true)) {
            [$refresh] = $this->issueRefreshToken($user, $clientId, $scopes, $refreshFamilyId);
        }

        $idToken = in_array('openid', $scopes, true)
            ? $this->jwt->encode(
                $this->baseClaims($user->id, $clientId, ['openid'], $request) + $this->identityClaims($user, $scopes),
                $this->keys->active()->private_key,
                $this->keys->active()->kid,
            )
            : null;

        $this->audit->log('token.issued', 'user', $user->id, 'token', $record->jti, [
            'client_id' => $clientId, 'scopes' => $scopes, 'kind' => 'user',
        ], $request);

        return [
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => max(0, $expiresAt->getTimestamp() - now()->getTimestamp()),
            'refresh_token' => $refresh,
            'scope' => implode(' ', $scopes),
            'id_token' => $idToken,
        ];
    }

    /**
     * client_credentials: the client itself is the subject, no refresh token.
     *
     * @param  string[]  $scopes
     * @return array{access_token: string, token_type: string, expires_in: int, scope: string}
     */
    public function issueForClient(OauthClient $client, array $scopes, ?Request $request = null): array
    {
        $request ??= request();
        [$token, $record, $expiresAt] = $this->mintJwt(
            subject: $client->client_id,
            subjectType: AccessToken::SUBJECT_CLIENT,
            scopes: $scopes,
            clientId: $client->client_id,
            user: null,
            request: $request,
        );

        $this->audit->log('token.issued', 'client', $client->client_id, 'token', $record->jti, [
            'client_id' => $client->client_id, 'scopes' => $scopes, 'kind' => 'client_credentials',
        ], $request);

        return [
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => max(0, $expiresAt->getTimestamp() - now()->getTimestamp()),
            'scope' => implode(' ', $scopes),
        ];
    }

    /**
     * Guest token: opaque, hashed at rest, no expiry by default.
     *
     * @param  string[]  $scopes
     */
    public function issueForGuest(GuestDevice $device, array $scopes, ?Request $request = null): array
    {
        $request ??= request();
        $ttl = (int) config('sso.guest.token_ttl', 0);
        $plain = 'sso_g_'.Str::random(48);
        $expiresAt = $ttl > 0 ? now()->addSeconds($ttl) : null;

        $record = AccessToken::create([
            'kind' => AccessToken::KIND_OPAQUE,
            'jti' => (string) Str::uuid(),
            'token_hash' => hash('sha256', $plain),
            'subject_type' => AccessToken::SUBJECT_GUEST,
            'guest_device_id' => $device->id,
            'client_id' => null,
            'scopes' => $scopes,
            'expires_at' => $expiresAt,
            'issued_ip' => $this->audit->ip($request),
            'user_agent' => $this->audit->agent($request),
        ]);

        $this->audit->log('token.issued', 'guest', $device->device_id, 'token', $record->jti, [
            'scopes' => $scopes, 'kind' => 'guest', 'expires_at' => $expiresAt?->toIso8601String(),
        ], $request);

        return [
            'access_token' => $plain,
            'token_type' => 'Bearer',
            'expires_in' => $expiresAt === null ? null : $ttl,
            'scope' => implode(' ', $scopes),
        ];
    }

    /**
     * Rotate a refresh token. Reuse of an already rotated token revokes the whole
     * family: that is the classic stolen-token signal.
     *
     * @return array{access_token: string, token_type: string, expires_in: int, refresh_token: string, scope: string}
     */
    public function refresh(string $plainRefreshToken, OauthClient $client, ?Request $request = null): array
    {
        $request ??= request();
        $record = RefreshToken::query()->where('token_hash', hash('sha256', $plainRefreshToken))->first();

        if ($record === null) {
            throw OAuthException::invalidGrant('Unknown refresh token');
        }

        if ($record->client_id !== $client->client_id) {
            throw OAuthException::invalidGrant('Refresh token was issued to another client');
        }

        if ($record->rotated_at !== null) {
            $this->revokeFamily($record->family_id, 'refresh token reuse');
            $this->audit->log('token.reuse_detected', 'user', $record->user_id, 'refresh_family', $record->family_id, [
                'client_id' => $client->client_id,
            ], $request);

            throw OAuthException::invalidGrant('Refresh token already used; the token family has been revoked');
        }

        if (! $record->isUsable()) {
            throw OAuthException::invalidGrant('Refresh token expired or revoked');
        }

        $user = $record->user;
        if ($user === null || ! $user->isActive()) {
            throw OAuthException::invalidGrant('Account is not active');
        }

        $scopes = $record->scopes;

        DB::transaction(function () use ($record) {
            $record->forceFill(['rotated_at' => now()])->save();
        });

        // The rotated token stays in the same family, so a later replay of any
        // ancestor revokes everything descended from this login.
        return $this->issueForUser($user, $client->client_id, $scopes, $request, $record->family_id);
    }

    /**
     * Resolve a bearer token to its stored record, or null when it is unknown,
     * expired, revoked or blacklisted.
     */
    public function resolve(string $plain): ?AccessToken
    {
        $record = $this->lookup($plain);
        if ($record === null || ! $record->isActive()) {
            return null;
        }

        if ($this->blacklist->isTokenBlocked($record->jti)) {
            return null;
        }

        if ($record->subject_type === AccessToken::SUBJECT_GUEST) {
            $device = $record->guestDevice;
            if ($device === null || ! $device->isActive() || $this->blacklist->isDeviceBlocked($device->device_id)) {
                return null;
            }
        }

        if ($record->subject_type === AccessToken::SUBJECT_USER) {
            $user = $record->user;
            if ($user === null || ! $user->isActive() || $this->blacklist->isUserBlocked($user->id)) {
                return null;
            }
        }

        if ($record->client_id !== null && $this->blacklist->isClientBlocked($record->client_id)) {
            return null;
        }

        return $record;
    }

    public function revoke(string $plain): void
    {
        $record = $this->lookup($plain);
        if ($record !== null && $record->revoked_at === null) {
            $record->forceFill(['revoked_at' => now()])->save();
            $this->audit->log('token.revoked', null, null, 'token', $record->jti);
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    public function introspect(string $plain): ?array
    {
        $record = $this->resolve($plain);
        if ($record === null) {
            return null;
        }

        $body = [
            'active' => true,
            'token_type' => 'Bearer',
            'scope' => implode(' ', $record->scopes ?? []),
            'client_id' => $record->client_id,
            'sub' => $this->subjectOf($record),
            'iss' => config('sso.issuer'),
            'iat' => $record->created_at?->getTimestamp(),
            'exp' => $record->expires_at?->getTimestamp(),
            'jti' => $record->jti,
            'token_kind' => $record->kind,
            'subject_type' => $record->subject_type,
        ];

        if ($record->user !== null) {
            $body['email'] = $record->user->email;
            $body['name'] = $record->user->name;
        }

        return $body;
    }

    private function subjectOf(AccessToken $record): ?string
    {
        return match ($record->subject_type) {
            AccessToken::SUBJECT_USER => (string) $record->user_id,
            AccessToken::SUBJECT_GUEST => $record->guestDevice?->device_id,
            default => $record->client_id,
        };
    }

    private function lookup(string $plain): ?AccessToken
    {
        // Guest tokens are opaque; user/client tokens are JWTs. Try the cheap
        // hash lookup first, then fall back to reading the jti from the JWT.
        $byHash = AccessToken::query()->where('token_hash', hash('sha256', $plain))->first();
        if ($byHash !== null) {
            return $byHash;
        }

        $claims = $this->decodeUnverified($plain);
        if ($claims === null || ! isset($claims['jti'])) {
            return null;
        }

        return AccessToken::query()->where('jti', (string) $claims['jti'])->first();
    }

    /**
     * Signature check only; no claim validation. Returns null for anything that
     * is not a token we signed.
     *
     * @return array<string, mixed>|null
     */
    public function decodeUnverified(string $plain): ?array
    {
        $parts = explode('.', $plain);
        if (count($parts) !== 3) {
            return null;
        }

        $header = json_decode(Jwt::unb64($parts[0]), true);
        $kid = is_array($header) ? ($header['kid'] ?? null) : null;
        $key = is_string($kid) ? $this->keys->publicKeyFor($kid) : null;
        if ($key === null) {
            return null;
        }

        try {
            return $this->jwt->decode($plain, $key->public_key);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @param  string[]  $scopes
     * @return array{0: string, 1: AccessToken, 2: \Illuminate\Support\Carbon}
     */
    private function mintJwt(
        string $subject,
        string $subjectType,
        array $scopes,
        ?string $clientId,
        ?User $user,
        Request $request,
    ): array {
        $key = $this->keys->active();
        $jti = (string) Str::uuid();
        $expiresAt = now()->addSeconds((int) config('sso.access_token_ttl', 604800));

        $claims = $this->baseClaims($user?->id, $clientId, $scopes, $request) + [
            'sub' => $subject,
            'jti' => $jti,
            'exp' => $expiresAt->getTimestamp(),
            'subject_type' => $subjectType,
        ];

        $token = $this->jwt->encode($claims, $key->private_key, $key->kid);

        $record = AccessToken::create([
            'kind' => AccessToken::KIND_JWT,
            'jti' => $jti,
            'subject_type' => $subjectType,
            'user_id' => $user?->id,
            'client_id' => $clientId,
            'scopes' => $scopes,
            'expires_at' => $expiresAt,
            'issued_ip' => $this->audit->ip($request),
            'user_agent' => $this->audit->agent($request),
        ]);

        return [$token, $record, $expiresAt];
    }

    /**
     * @param  string[]  $scopes
     * @return array<string, mixed>
     */
    private function baseClaims(?int $userId, ?string $clientId, array $scopes, Request $request): array
    {
        $claims = [
            'iss' => config('sso.issuer'),
            'aud' => $clientId ?? 'sso',
            'iat' => now()->getTimestamp(),
            'nbf' => now()->getTimestamp(),
            'scope' => implode(' ', $scopes),
        ];

        if ($userId !== null) {
            $claims['uid'] = (string) $userId;
        }

        return $claims;
    }

    /**
     * @param  string[]  $scopes
     * @return array<string, mixed>
     */
    private function identityClaims(User $user, array $scopes): array
    {
        $claims = ['sub' => (string) $user->id];
        if (in_array('profile', $scopes, true)) {
            $claims['name'] = $user->name;
            $claims['created_at'] = $user->created_at?->getTimestamp();
        }
        if (in_array('email', $scopes, true)) {
            $claims['email'] = $user->email;
            $claims['email_verified'] = true;
        }

        return $claims;
    }

    /**
     * @param  string[]  $scopes
     * @return array{0: string, 1: RefreshToken}
     */
    private function issueRefreshToken(User $user, string $clientId, array $scopes, ?string $familyId = null): array
    {
        $plain = 'sso_r_'.Str::random(48);
        $record = RefreshToken::create([
            'token_hash' => hash('sha256', $plain),
            'family_id' => $familyId ?? (string) Str::uuid(),
            'user_id' => $user->id,
            'client_id' => $clientId,
            'scopes' => $scopes,
            'expires_at' => now()->addSeconds((int) config('sso.refresh_token_ttl', 2592000)),
        ]);

        return [$plain, $record];
    }

    private function revokeFamily(string $familyId, string $reason): void
    {
        RefreshToken::query()->where('family_id', $familyId)->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);

        $this->audit->log('token.family_revoked', null, null, 'refresh_family', $familyId, ['reason' => $reason]);
    }
}
