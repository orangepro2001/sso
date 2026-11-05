<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The console gets its own session cookie.
 *
 * Two identities live in this application: console administrators (guard `admin`)
 * and SSO users (guard `web`). If they shared one session cookie, "I am signed in"
 * would be ambiguous — an administrator would appear signed in while every client
 * still bounced them to the user sign-in page, and signing out of one would sign
 * out of the other.
 *
 * Switching the cookie name for console paths keeps them fully independent:
 *
 *   sso_session        -> the SSO user session; the only one OAuth ever consults
 *   sso_admin_session  -> the console session; never used as a client identity
 *
 * Must run before EncryptCookies/StartSession, which read the cookie name once per
 * request.
 */
class ConsoleSession
{
    public const COOKIE = 'sso_admin_session';

    public function handle(Request $request, Closure $next): Response
    {
        if ($request->is('admin', 'admin/*')) {
            config(['session.cookie' => self::COOKIE]);
        }

        return $next($request);
    }
}
