<?php

use App\Http\Middleware\AuthenticateAdmin;
use App\Http\Middleware\AuthenticateToken;
use App\Http\Middleware\ForceHttpsRootUrl;
use App\Http\Middleware\SecurityHeaders;
use App\Services\AccountRuleException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpKernel\Exception\HttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: function (): void {
            // OAuth endpoints live at the root of /sso (no /api prefix) but still
            // need the session so /oauth/authorize can resume after login.
            Route::middleware('web')->group(base_path('routes/oauth.php'));
        },
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // caddy terminates TLS on 127.0.0.1 and is the only front end.
        $middleware->trustProxies(
            at: env('SSO_TRUSTED_PROXIES', '127.0.0.1,::1'),
            headers: Request::HEADER_X_FORWARDED_FOR
                | Request::HEADER_X_FORWARDED_HOST
                | Request::HEADER_X_FORWARDED_PORT
                | Request::HEADER_X_FORWARDED_PROTO,
        );

        // Machine-to-machine endpoints cannot carry a CSRF token.
        $middleware->validateCsrfTokens(except: [
            'oauth/token',
            'oauth/introspect',
            'oauth/revoke',
        ]);

        // ForceHttpsRootUrl must run *before* StartSession: the session stores the
        // "previous URL" (used by back()/redirect()->back()) and the CSRF referer,
        // and those values have to be built from the public root. Appending it after
        // the group (as is tempting) stores /admin/login instead of /sso/admin/login
        // and every validation-failure redirect lands on a 404.
        $middleware->prependToGroup('web', ForceHttpsRootUrl::class);
        $middleware->prependToGroup('api', ForceHttpsRootUrl::class);

        $middleware->web(append: [
            SecurityHeaders::class,
        ]);

        $middleware->alias([
            'admin' => AuthenticateAdmin::class,
            'token' => AuthenticateToken::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('oauth/*') || $request->is('.well-known/*') || $request->is('api/*') || $request->expectsJson()
        );

        // An account rule (UserAccounts) reads like a validation error wherever it
        // was hit: a field message on the form, or a 422 for an API caller.
        $exceptions->render(function (AccountRuleException $e, Request $request) {
            if ($request->is('api/*') || $request->expectsJson()) {
                return response()->json(['message' => $e->getMessage(), 'errors' => [$e->field => [$e->getMessage()]]], 422);
            }

            return back()->withErrors([$e->field => $e->getMessage()])->withInput();
        });

        // The sign-in form sent twice: the first submit signed in and regenerated the
        // session, so the second carries a stale CSRF token. The work-report desktop
        // client showed "419 PAGE EXPIRED" in place of the application (2026-11-07).
        // Signed in: carry on where the sign-in was going (the parked or just-served
        // authorize request). Not signed in: the form again, with a word on why.
        $exceptions->render(function (HttpException $e, Request $request) {
            if ($e->getStatusCode() !== 419 || ! $request->isMethod('post') || ! $request->routeIs('login.store')) {
                return null;
            }
            if (Auth::guard('web')->check()) {
                $last = $request->session()->get('oauth.last');
                $resume = $request->session()->get('oauth.pending')
                    ?? (is_array($last) && ($last['at'] ?? 0) > time() - 120 ? $last['params'] : null);

                return $resume ? redirect()->route('oauth.authorize', $resume) : redirect()->route('home');
            }

            return redirect()->route('login', array_filter(['next' => $request->query('next')]))
                ->withErrors(['username' => '로그인 화면이 오래되었습니다. 다시 로그인하세요.']);
        });
    })->create();
