<?php

namespace App\Http\Middleware;

use App\Services\PublicUrlRewriter;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;
use Symfony\Component\HttpFoundation\Response;

/**
 * The service is proxied under a mount point (/sso): caddy strips the prefix
 * before forwarding, so the framework only ever sees "/admin/login" while clients
 * must see "/sso/admin/login".
 *
 * Three things need correcting, at three different moments:
 *
 *  1. URL generation (route(), url(), form actions) — URL::forceRootUrl. Must run
 *     before StartSession, because the session and the CSRF layer resolve URLs too.
 *
 *  2. The session's *existing* "previous URL", which StartSession wrote on an
 *     earlier request from $request->fullUrl() — a value forceRootUrl does not
 *     touch. Rewritten on the way in, so redirect()->back() (and therefore every
 *     validation-failure redirect) replays a prefixed URL.
 *
 *  3. The "previous URL" this request stores for the next one. StartSession writes
 *     it after the inner middlewares return and saves the session immediately, so
 *     it is corrected and re-saved on the way out.
 */
class ForceHttpsRootUrl
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('sso.force_root_url', true)) {
            return $next($request);
        }

        $rewriter = PublicUrlRewriter::fromConfig();

        URL::forceRootUrl($rewriter->root($request->getHost()));
        URL::forceScheme($rewriter->scheme());

        // (2) the URL left behind by an earlier request
        $this->rewriteStoredPreviousUrl($request, $rewriter);

        $response = $next($request);

        // (3) the URL this request leaves behind, already persisted by StartSession
        if ($this->rewriteStoredPreviousUrl($request, $rewriter) && $request->hasSession()) {
            $request->session()->save();
        }

        return $response;
    }

    /**
     * @return bool whether the stored URL had to be rewritten
     */
    private function rewriteStoredPreviousUrl(Request $request, PublicUrlRewriter $rewriter): bool
    {
        if (! $request->hasSession()) {
            return false;
        }

        $previous = $request->session()->previousUrl();
        if (! is_string($previous) || $previous === '') {
            return false;
        }

        $fixed = $rewriter->prefix($previous);
        if ($fixed === $previous) {
            return false;
        }

        $request->session()->setPreviousUrl($fixed);

        return true;
    }
}
