<?php

namespace App\Providers;

use App\Services\AuditLogger;
use App\Services\BlacklistService;
use App\Services\ClientAuthenticator;
use App\Services\GuestService;
use App\Services\Jwt;
use App\Services\SigningKeyService;
use App\Services\TokenService;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Validation\Rules\Password;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Jwt::class);
        $this->app->singleton(SigningKeyService::class);
        $this->app->singleton(AuditLogger::class);
        $this->app->singleton(BlacklistService::class);
        $this->app->singleton(ClientAuthenticator::class);
        $this->app->singleton(TokenService::class);
        $this->app->singleton(GuestService::class);
    }

    public function boot(): void
    {
        Password::defaults(fn () => Password::min(12));

        // A machine-run guest call is cheap, but a loop should still be capped.
        RateLimiter::for('oauth-guest', fn (Request $request) => Limit::perMinute(120)->by($request->ip()));
    }
}
