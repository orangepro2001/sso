<?php

namespace App\Support;

use Illuminate\Http\Request;

/**
 * Where a sign-in may send the browser next.
 *
 * `/login?next=…` is what lets a person who signed out of *another* application come
 * back to it after signing in here — the alternative is leaving them on this page
 * wondering whether anything happened.
 *
 * Only two shapes are accepted, because a login form that redirects wherever it is told
 * is an open redirect:
 *   · a path starting with a single `/` (relative to this host);
 *   · an absolute URL whose host is this host (an application mounted beside /sso).
 */
final class SafeRedirect
{
    public static function target(Request $request, ?string $next): ?string
    {
        $next = trim((string) $next);

        if ($next === '') {
            return null;
        }

        // `//evil.test` is a protocol-relative URL, not a path.
        if (str_starts_with($next, '/') && ! str_starts_with($next, '//')) {
            return $next;
        }

        $parts = parse_url($next);

        if ($parts === false || ! isset($parts['host'])) {
            return null;
        }

        if (strcasecmp((string) $parts['host'], $request->getHost()) !== 0) {
            return null;
        }

        $scheme = $parts['scheme'] ?? 'https';

        if (! in_array(strtolower($scheme), ['http', 'https'], true)) {
            return null;
        }

        return $next;
    }

    /**
     * The same value as an absolute URL.
     *
     * A `next` of `/report` means "on this host, at the root" — the applications live
     * beside the mount point, not under it, so handing `/report` to the redirector
     * would produce `/sso/report`. Everything stored in `url.intended` is absolute for
     * exactly this reason.
     */
    public static function absolute(Request $request, string $next): string
    {
        if (str_starts_with($next, '/') && ! str_starts_with($next, '//')) {
            return $request->getSchemeAndHttpHost().$next;
        }

        return $next;
    }
}
