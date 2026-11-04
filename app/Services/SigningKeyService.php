<?php

namespace App\Services;

use App\Models\SigningKey;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Owns the RSA key pair used to sign access tokens. Keys live in the database
 * (private half encrypted with APP_KEY) so the container rootfs can be read-only
 * and no key material has to be baked into an image.
 */
class SigningKeyService
{
    private ?SigningKey $active = null;

    public function active(): SigningKey
    {
        if ($this->active !== null) {
            return $this->active;
        }

        $key = SigningKey::query()->where('active', true)->latest('id')->first();

        return $this->active = $key ?? $this->generate();
    }

    /**
     * All keys that may still have live tokens in circulation.
     *
     * @return Collection<int, SigningKey>
     */
    public function publishable(): Collection
    {
        return SigningKey::query()->orderByDesc('active')->orderByDesc('id')->get();
    }

    public function rotate(): SigningKey
    {
        SigningKey::query()->where('active', true)->update(['active' => false, 'retired_at' => now()]);
        $this->active = null;

        return $this->active();
    }

    private function generate(): SigningKey
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 3072,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false || ! openssl_pkey_export($resource, $privatePem)) {
            throw new RuntimeException('Could not generate an RSA key pair');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false || ! isset($details['key'])) {
            throw new RuntimeException('Could not read the generated public key');
        }

        return SigningKey::create([
            'kid' => Str::lower(Str::random(16)),
            'alg' => Jwt::ALG,
            'private_key' => $privatePem,
            'public_key' => $details['key'],
            'active' => true,
        ]);
    }

    public function publicKeyFor(string $kid): ?SigningKey
    {
        return SigningKey::query()->where('kid', $kid)->first();
    }
}
