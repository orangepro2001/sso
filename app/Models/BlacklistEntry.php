<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class BlacklistEntry extends Model
{
    public const KIND_DEVICE = 'device';

    public const KIND_USER = 'user';

    public const KIND_TOKEN = 'token';

    public const KIND_CLIENT = 'client';

    protected $fillable = ['kind', 'value', 'reason', 'created_by', 'expires_at'];

    protected $casts = ['expires_at' => 'datetime'];

    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }

    public function isLive(): bool
    {
        return $this->expires_at === null || $this->expires_at->isFuture();
    }
}
