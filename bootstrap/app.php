<?php

use App\Http\Middleware\AuthenticateAdmin;
use App\Http\Middleware\ForceHttpsRootUrl;
use App\Http\Middleware\SecurityHeaders;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
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
            'oauth/guest',
        ]);

        // ForceHttpsRootUrl must run *before* StartSession: the session stores the
        // "previous URL" (used by back()/redirect()->back()) and the CSRF referer,
        // and those values have to be built from the public root. Appending it after
        // the group (as is tempting) stores /admin/login instead of /sso/admin/login
        // and every validation-failure redirect lands on a 404.
        $middleware->prependToGroup('web', ForceHttpsRootUrl::class);

        $middleware->web(append: [
            SecurityHeaders::class,
        ]);

        $middleware->alias([
            'admin' => AuthenticateAdmin::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('oauth/*') || $request->is('.well-known/*') || $request->expectsJson()
        );
    })->create();
