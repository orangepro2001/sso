<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class GuestDevice extends Model
{
    use HasFactory;

    public const STATUS_ACTIVE = 'active';

    public const STATUS_BLACKLISTED = 'blacklisted';

    protected $fillable = [
        'device_id', 'status', 'request_count', 'first_seen_ip', 'last_seen_ip',
        'first_user_agent', 'last_user_agent', 'first_seen_at', 'last_seen_at',
        'reviewed_at', 'reviewed_by', 'note',
    ];

    protected $casts = [
        'first_seen_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'reviewed_at' => 'datetime',
        'request_count' => 'integer',
    ];

    public function isActive(): bool
    {
        return $this->status === self::STATUS_ACTIVE;
    }

    public function tokens(): HasMany
    {
        return $this->hasMany(AccessToken::class);
    }

    public function reviewer(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'reviewed_by');
    }
}
