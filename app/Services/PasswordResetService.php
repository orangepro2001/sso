<?php

namespace App\Services;

use App\Models\AccessToken;
use App\Models\RefreshToken;
use App\Models\User;
use App\Models\UserPasswordReset;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * One-time password reset links, and the credential revocation that goes with any
 * password change.
 *
 * No mail: users have no address, so the link is minted by an administrator and
 * handed over out of band. Only the SHA-256 of the token is stored.
 */
class PasswordResetService
{
    /**
     * Issue a link for a user. Any earlier unused link for the same user is
     * revoked first: a person following an old link must not be able to set a
     * password behind the administrator's back.
     *
     * @return array{0: string, 1: UserPasswordReset} plaintext token and its row
     */
    public function issue(User $user, ?int $adminId = null): array
    {
        UserPasswordReset::query()
            ->where('user_id', $user->id)
            ->whereNull('used_at')
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);

        $plain = 'sso_pw_'.Str::random(48);

        $row = UserPasswordReset::create([
            'user_id' => $user->id,
            'token_hash' => $this->hash($plain),
            'created_by' => $adminId,
            'expires_at' => $this->expiry(),
        ]);

        return [$plain, $row];
    }

    /**
     * The public URL to hand over. Built from the issuer, so it is the address a
     * human can actually open, not the container's internal origin.
     */
    public function url(string $plain): string
    {
        return rtrim((string) config('sso.issuer'), '/').'/password/reset/'.$plain;
    }

    public function find(string $plain): ?UserPasswordReset
    {
        return UserPasswordReset::query()
            ->where('token_hash', $this->hash($plain))
            ->first();
    }

    /**
     * Mark the link spent. Called only after the password has been changed.
     */
    public function consume(UserPasswordReset $reset, ?string $ip = null): void
    {
        $reset->forceFill([
            'used_at' => now(),
            'used_ip' => $ip === null ? null : substr($ip, 0, 45),
        ])->save();
    }

    /**
     * A password change ends every session that password could have opened.
     * Short-lived access tokens are revoked too, so "I reset my password" actually
     * means "nobody stays signed in". $keepJti spares one access token: the one an
     * API client used to make this very change.
     */
    public function revokeCredentials(User $user, ?string $keepJti = null): array
    {
        $access = AccessToken::query()
            ->where('user_id', $user->id)
            ->whereNull('revoked_at')
            ->when($keepJti !== null, fn ($q) => $q->where('jti', '!=', $keepJti))
            ->update(['revoked_at' => now()]);

        $refresh = RefreshToken::query()
            ->where('user_id', $user->id)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);

        return ['access_tokens' => $access, 'refresh_tokens' => $refresh];
    }

    private function expiry(): Carbon
    {
        return now()->addSeconds((int) config('sso.reset_link_ttl', 86400));
    }

    private function hash(string $plain): string
    {
        return hash('sha256', $plain);
    }
}
