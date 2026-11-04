<?php

namespace App\Services;

use App\Models\SigningKey;
use RuntimeException;

/**
 * Minimal, dependency-free RS256 JWS implementation.
 *
 * Only the algorithm we actually use is implemented (no "alg" confusion possible:
 * a token whose header says anything but RS256 is rejected outright).
 */
final class Jwt
{
    public const ALG = 'RS256';

    /**
     * @param  array<string, mixed>  $claims
     */
    public static function encode(array $claims, string $privateKeyPem, string $kid): string
    {
        $header = ['typ' => 'JWT', 'alg' => self::ALG, 'kid' => $kid];
        $signingInput = self::b64(json_encode($header, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR))
            .'.'.self::b64(json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

        $signature = '';
        $key = openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw new RuntimeException('Invalid signing key');
        }
        if (! openssl_sign($signingInput, $signature, $key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Could not sign the token');
        }

        return $signingInput.'.'.self::b64($signature);
    }

    /**
     * Verifies the signature against the published key and returns the claims.
     *
     * @return array<string, mixed>
     */
    public static function decode(string $token, string $publicKeyPem): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new RuntimeException('Malformed token');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $header = json_decode(self::unb64($encodedHeader), true);
        if (! is_array($header) || ($header['alg'] ?? null) !== self::ALG) {
            throw new RuntimeException('Unsupported algorithm');
        }

        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            throw new RuntimeException('Invalid verification key');
        }

        $ok = openssl_verify(
            $encodedHeader.'.'.$encodedPayload,
            self::unb64($encodedSignature),
            $key,
            OPENSSL_ALGO_SHA256
        );

        if ($ok !== 1) {
            throw new RuntimeException('Bad signature');
        }

        $claims = json_decode(self::unb64($encodedPayload), true);
        if (! is_array($claims)) {
            throw new RuntimeException('Malformed payload');
        }

        return $claims;
    }

    /**
     * JWK set for the discovery document (public halves only).
     *
     * @param  iterable<SigningKey>  $keys
     * @return array<int, array<string, string>>
     */
    public static function jwks(iterable $keys): array
    {
        $out = [];
        foreach ($keys as $key) {
            $n = self::modulus($key->public_key);
            if ($n !== null) {
                $out[] = [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => $key->alg,
                    'kid' => $key->kid,
                    'n' => $n,
                    'e' => 'AQAB',
                ];
            }
        }

        return $out;
    }

    private static function modulus(string $publicKeyPem): ?string
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            return null;
        }
        $details = openssl_pkey_get_details($key);
        $raw = $details['rsa']['n'] ?? null;

        return $raw === null ? null : self::b64($raw);
    }

    public static function b64(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function unb64(string $data): string
    {
        $padded = str_pad(strtr($data, '-_', '+/'), (int) (ceil(strlen($data) / 4) * 4), '=');

        return base64_decode($padded, true) ?: '';
    }
}
