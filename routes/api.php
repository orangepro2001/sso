<?php

use App\Http\Controllers\Api\MeController;
use App\Http\Controllers\Api\UserController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Account API (docs/api.md)
|--------------------------------------------------------------------------
| Stateless: an access token from the authorization-code flow, sent as
| `Authorization: Bearer`. No session, no CSRF token.
*/

Route::middleware(['token', 'throttle:120,1'])->group(function () {
    Route::get('me', [MeController::class, 'show'])->name('api.me');
    Route::patch('me', [MeController::class, 'update'])->name('api.me.update');
    Route::post('me/avatar', [MeController::class, 'avatar'])->name('api.me.avatar');
    Route::delete('me/avatar', [MeController::class, 'avatarRemove'])->name('api.me.avatar.remove');
    Route::put('me/password', [MeController::class, 'password'])->name('api.me.password');
});

Route::middleware(['token:admin', 'throttle:240,1'])->prefix('users')->name('api.users.')->group(function () {
    Route::get('/', [UserController::class, 'index'])->name('index');
    Route::post('/', [UserController::class, 'store'])->name('store');
    Route::get('{user}', [UserController::class, 'show'])->name('show');
    Route::patch('{user}', [UserController::class, 'update'])->name('update');
    Route::delete('{user}', [UserController::class, 'destroy'])->name('destroy');
    Route::post('{user}/password', [UserController::class, 'password'])->name('password');
    Route::post('{user}/reset-link', [UserController::class, 'resetLink'])->name('reset-link');
    Route::post('{user}/avatar', [UserController::class, 'avatar'])->name('avatar');
    Route::delete('{user}/avatar', [UserController::class, 'avatarRemove'])->name('avatar.remove');
    Route::post('{user}/sign-out', [UserController::class, 'signOut'])->name('sign-out');
});
