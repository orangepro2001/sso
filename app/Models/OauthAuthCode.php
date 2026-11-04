<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class OauthAuthCode extends Model
{
    protected $fillable = [
        'code_hash', 'client_id', 'user_id', 'redirect_uri', 'scopes',
        'code_challenge', 'code_challenge_method', 'expires_at', 'consumed_at',
    ];

    protected $casts = [
        'scopes' => 'array',
        'expires_at' => 'datetime',
        'consumed_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
