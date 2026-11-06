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

    /** The console is open to this role only (AuthenticateAdmin). */
    public const ROLE_SUPER_ADMIN = 'super_admin';

    public const ROLE_USER = 'user';

    public const ROLES = [self::ROLE_USER, self::ROLE_SUPER_ADMIN];

    protected $fillable = [
        'name', 'username', 'role', 'password', 'status', 'last_login_at', 'last_login_ip', 'created_by', 'note',
        'avatar_path', 'avatar_mime', 'avatar_updated_at',
    ];

    protected $hidden = ['password', 'remember_token'];

    protected $casts = [
        'password' => 'hashed',
        'last_login_at' => 'datetime',
        'avatar_updated_at' => 'datetime',
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

    /**
     * A signed, cache-friendly URL for the picture.
     *
     * Public on purpose: other applications read it server-side from the `picture`
     * claim and cannot carry a session. The signature is what makes it safe — the
     * path is unguessable without it, and it changes when the picture does.
     */
    public function avatarUrl(): ?string
    {
        if ($this->avatar_path === null) {
            return null;
        }

        $version = (string) ($this->avatar_updated_at?->getTimestamp() ?? 0);

        return route('avatar.show', [
            'user' => $this->id,
            'v' => $version,
            'sig' => hash_hmac('sha256', $this->id.'|'.$version, (string) config('app.key')),
        ]);
    }

    public function hasAvatar(): bool
    {
        return $this->avatar_path !== null;
    }

    public function isSuperAdmin(): bool
    {
        return $this->role === self::ROLE_SUPER_ADMIN;
    }

    public function isActive(): bool
    {
        return $this->status === self::STATUS_ACTIVE;
    }

    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }
}
