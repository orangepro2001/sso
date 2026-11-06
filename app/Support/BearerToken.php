<?php

namespace App\Support;

use Illuminate\Http\Request;

/** The bearer token of a request (RFC 6750 §2.1, with the §2.2 form fallback). */
final class BearerToken
{
    public static function from(Request $request): ?string
    {
        $header = (string) $request->header('Authorization', '');
        if (preg_match('/^Bearer\s+(\S+)$/i', $header, $m) === 1) {
            return $m[1];
        }

        $fallback = $request->input('access_token');

        return is_string($fallback) && $fallback !== '' ? $fallback : null;
    }
}
