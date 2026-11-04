<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * An SSO end user. Identified by username alone: there is no e-mail address and
 * no verification flow to go with it.
 */
class User extends Authenticatable
{
    use HasFactory;

    public const STATUS_ACTIVE = 'active';

    public const STATUS_DISABLED = 'disabled';

    protected $fillable = [
        'name', 'username', 'password', 'status', 'last_login_at', 'last_login_ip', 'created_by', 'note',
    ];

    protected $hidden = ['password', 'remember_token'];

    protected $casts = [
        'password' => 'hashed',
        'last_login_at' => 'datetime',
    ];

    /**
     * Usernames are case-insensitive to humans, so they are stored lower-case and
     * compared lower-case. `.` and `-` and `_` are allowed because they appear in
     * real login names.
     */
    public const USERNAME_PATTERN = '/^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$/';

    public static function booted(): void
    {
        static::saving(function (User $user) {
            $user->username = strtolower(trim((string) $user->username));
        });
    }

    public function isActive(): bool
    {
        return $this->status === self::STATUS_ACTIVE;
    }

    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }
}
