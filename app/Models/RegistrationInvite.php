<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/** A one-time registration code (database/migrations/…create_registration_invites_table). */
class RegistrationInvite extends Model
{
    protected $fillable = [
        'code_hash', 'note', 'created_by', 'expires_at', 'used_at', 'used_ip', 'used_by', 'revoked_at',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'used_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'used_by');
    }

    public function isUsable(): bool
    {
        return $this->used_at === null
            && $this->revoked_at === null
            && $this->expires_at->isFuture();
    }

    /** Why it is not usable, for the audit log and the page. */
    public function reason(): string
    {
        return match (true) {
            $this->revoked_at !== null => 'revoked',
            $this->used_at !== null => 'used',
            $this->expires_at->isPast() => 'expired',
            default => 'usable',
        };
    }
}
