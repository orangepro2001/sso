<?php

namespace App\Services;

use App\Models\BlacklistEntry;

/**
 * Deny list lookups. Guest tokens are long lived (or eternal), so the blacklist
 * is what makes revocation effective: it is consulted on every introspection and
 * on every userinfo / API call that resolves a token.
 */
class BlacklistService
{
    public function isDeviceBlocked(string $deviceId): bool
    {
        return $this->isBlocked(BlacklistEntry::KIND_DEVICE, $deviceId);
    }

    public function isUserBlocked(int|string $userId): bool
    {
        return $this->isBlocked(BlacklistEntry::KIND_USER, (string) $userId);
    }

    public function isTokenBlocked(string $jti): bool
    {
        return $this->isBlocked(BlacklistEntry::KIND_TOKEN, $jti);
    }

    public function isClientBlocked(string $clientId): bool
    {
        return $this->isBlocked(BlacklistEntry::KIND_CLIENT, $clientId);
    }

    public function isBlocked(string $kind, string $value): bool
    {
        return BlacklistEntry::query()
            ->where('kind', $kind)
            ->where('value', $value)
            ->where(fn ($q) => $q->whereNull('expires_at')->orWhere('expires_at', '>', now()))
            ->exists();
    }

    public function block(string $kind, string $value, ?string $reason = null, ?int $adminId = null): BlacklistEntry
    {
        return BlacklistEntry::query()->updateOrCreate(
            ['kind' => $kind, 'value' => $value],
            ['reason' => $reason, 'created_by' => $adminId, 'expires_at' => null],
        );
    }

    public function unblock(string $kind, string $value): void
    {
        BlacklistEntry::query()->where('kind', $kind)->where('value', $value)->delete();
    }
}
