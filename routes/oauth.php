<?php

use App\Http\Controllers\HealthController;
use App\Http\Controllers\OAuth\AuthorizeController;
use App\Http\Controllers\OAuth\DiscoveryController;
use App\Http\Controllers\OAuth\IntrospectController;
use App\Http\Controllers\OAuth\TokenController;
use App\Http\Controllers\OAuth\UserInfoController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| OAuth 2.0 / OpenID Connect endpoints
|--------------------------------------------------------------------------
| The whole service is mounted under /sso by the reverse proxy, so route paths
| here are relative to that prefix.
*/

Route::get('.well-known/openid-configuration', [DiscoveryController::class, 'openidConfiguration']);
Route::get('.well-known/jwks.json', [DiscoveryController::class, 'jwks']);

Route::get('oauth/authorize', AuthorizeController::class)->name('oauth.authorize');
Route::post('oauth/token', TokenController::class)->name('oauth.token');
Route::post('oauth/introspect', [IntrospectController::class, 'introspect'])->name('oauth.introspect');
Route::post('oauth/revoke', [IntrospectController::class, 'revoke'])->name('oauth.revoke');
Route::get('oauth/userinfo', UserInfoController::class)->name('oauth.userinfo');
Route::post('oauth/userinfo', UserInfoController::class)->name('oauth.userinfo.post');

// Plain controller (no closure) so that `route:cache` works in the image.
Route::get('healthz', HealthController::class)->name('healthz');
