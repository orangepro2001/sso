<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AccessToken extends Model
{
    public const KIND_JWT = 'jwt';

    public const KIND_OPAQUE = 'opaque';

    public const SUBJECT_USER = 'user';

    public const SUBJECT_CLIENT = 'client';

    protected $fillable = [
        'kind', 'jti', 'token_hash', 'subject_type', 'user_id',
        'client_id', 'scopes', 'expires_at', 'revoked_at', 'issued_ip', 'user_agent',
    ];

    protected $casts = [
        'scopes' => 'array',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function isActive(): bool
    {
        if ($this->revoked_at !== null) {
            return false;
        }

        return $this->expires_at === null || $this->expires_at->isFuture();
    }
}
