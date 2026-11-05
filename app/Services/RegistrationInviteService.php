<?php

namespace App\Services;

use App\Models\RegistrationInvite;
use Illuminate\Support\Str;

/**
 * Minting and looking up one-time registration codes.
 *
 * Same shape as the password-reset links: no mail, no public sign-up, the
 * administrator hands the credential over out of band, and the database only keeps
 * a hash of it.
 */
class RegistrationInviteService
{
    /** 30 days: long enough to survive a vacation, short enough to be a credential. */
    public const TTL_DAYS = 30;

    /**
     * @return array{0: string, 1: RegistrationInvite} plaintext code and its row
     */
    public function issue(?string $note, ?int $adminId): array
    {
        $plain = 'sso_inv_'.Str::random(32);

        $row = RegistrationInvite::create([
            'code_hash' => $this->hash($plain),
            'note' => $note,
            'created_by' => $adminId,
            'expires_at' => now()->addDays(self::TTL_DAYS),
        ]);

        return [$plain, $row];
    }

    public function find(string $plain): ?RegistrationInvite
    {
        return RegistrationInvite::query()->where('code_hash', $this->hash($plain))->first();
    }

    /** The address a person opens; built from the issuer so it carries /sso. */
    public function url(string $plain): string
    {
        return rtrim((string) config('sso.issuer'), '/').'/register/'.$plain;
    }

    public function hash(string $plain): string
    {
        return hash('sha256', $plain);
    }
}
