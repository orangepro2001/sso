<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class OauthClient extends Model
{
    use HasFactory;

    public const TYPE_PUBLIC = 'public';

    public const TYPE_CONFIDENTIAL = 'confidential';

    protected $fillable = [
        'client_id', 'name', 'type', 'secret_hash', 'redirect_uris', 'allowed_scopes', 'active', 'created_by', 'note',
    ];

    protected $hidden = ['secret_hash'];

    protected $casts = [
        'redirect_uris' => 'array',
        'allowed_scopes' => 'array',
        'active' => 'boolean',
    ];

    public static function generateClientId(): string
    {
        return 'sso_'.Str::lower(Str::random(24));
    }

    public function creator(): BelongsTo
    {
        return $this->belongsTo(Admin::class, 'created_by');
    }

    public function isPublic(): bool
    {
        return $this->type === self::TYPE_PUBLIC;
    }

    /**
     * Exact match against the registered redirect URIs. No wildcards on purpose:
     * an open redirect in an authorization server is a total compromise.
     */
    public function hasRedirectUri(string $uri): bool
    {
        return in_array($uri, $this->redirect_uris ?? [], true);
    }

    public function verifySecret(?string $secret): bool
    {
        if ($this->isPublic()) {
            return true; // PKCE instead of a secret
        }

        return is_string($secret) && $secret !== '' && password_verify($secret, (string) $this->secret_hash);
    }

    /**
     * @param  string[]  $requested
     * @return string[]
     */
    public function grantedScopes(array $requested): array
    {
        $allowed = $this->allowed_scopes ?? [];
        $granted = array_values(array_intersect($requested, $allowed));

        return $granted === [] ? array_values(array_intersect(['openid', 'profile'], $allowed)) : $granted;
    }
}
