<?php

namespace App\Providers;

use App\Services\AuditLogger;
use App\Services\ClientAuthenticator;
use App\Services\Jwt;
use App\Services\SigningKeyService;
use App\Services\TokenService;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Jwt::class);
        $this->app->singleton(SigningKeyService::class);
        $this->app->singleton(AuditLogger::class);
        $this->app->singleton(ClientAuthenticator::class);
        $this->app->singleton(TokenService::class);
    }

    public function boot(): void {}
}
