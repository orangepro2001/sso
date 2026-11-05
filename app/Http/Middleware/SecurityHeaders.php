<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * A small, boring set of security headers. HSTS is left to the TLS terminator
 * (caddy / tailscale serve) so this service stays scheme agnostic.
 */
class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set(
            'Content-Security-Policy',
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        );

        // Token endpoints never cache, and neither do authenticated pages: a console
        // page restored from the back/forward cache can carry links from an older
        // build, which is how a stale "/admin/devices" without the /sso prefix
        // reached a browser once.
        if ($request->is('oauth/*', '.well-known/*', 'userinfo', 'api/*', 'admin/*', 'admin', 'login', 'logout')) {
            $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            $response->headers->set('Pragma', 'no-cache');
        }

        return $response;
    }
}
