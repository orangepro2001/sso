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
        // A machine-run guest call is cheap, but a runaway loop should still be
        // capped. Keyed by device id so one busy device cannot exhaust the budget
        // of every other device behind the same NAT address.
        RateLimiter::for('oauth-guest', function (Request $request) {
            $device = $request->input('device_id');
            $key = is_string($device) && trim($device) !== '' ? 'dev:'.trim($device) : 'ip:'.$request->ip();

            return Limit::perMinute(120)->by($key);
        });
    }
}
