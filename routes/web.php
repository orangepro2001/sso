<?php

use App\Http\Controllers\Admin\AuthController;
use App\Http\Controllers\Admin\ClientController;
use App\Http\Controllers\Admin\DashboardController;
use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\Auth\PasswordResetController;
use App\Http\Controllers\Auth\ProfileController;
use App\Http\Controllers\Auth\RegistrationController;
use App\Http\Controllers\Auth\UserLoginController;
use App\Http\Controllers\AvatarController;
use App\Http\Controllers\HomeController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Console (session based) routes
|--------------------------------------------------------------------------
*/

Route::get('/', HomeController::class)->name('home');

// End-user authentication, resumed by /oauth/authorize afterwards.
// The GET is outside `guest:web` on purpose: somebody arriving with ?next= while this
// session is still alive must be sent to `next`, not bounced to the home page.
Route::get('login', [UserLoginController::class, 'show'])->name('login');
Route::post('login', [UserLoginController::class, 'store'])
    ->middleware('guest:web')
    ->name('login.store');
Route::post('logout', [UserLoginController::class, 'destroy'])->middleware('auth:web')->name('logout');

// Open self-registration. Old invite links (register/{code}) still land on the form;
// the code is ignored. Rate limited so a script cannot mint accounts in bulk.
Route::get('register/{code?}', [RegistrationController::class, 'show'])
    ->middleware('guest:web')
    ->middleware('throttle:30,1')
    ->name('register');
Route::post('register/{code?}', [RegistrationController::class, 'store'])
    ->middleware('guest:web')
    ->middleware('throttle:10,1')
    ->name('register.store');

// Profile pictures are read by other applications from the `picture` claim, so the
// route is anonymous and the URL carries an HMAC (AvatarController).
Route::get('avatar/{user}/{v}', AvatarController::class)
    ->middleware('throttle:120,1')
    ->name('avatar.show');

// The account a person owns: their name, their password, where they are signed in.
Route::middleware('auth:web')->group(function () {
    Route::get('account', [ProfileController::class, 'show'])->name('account');
    Route::put('account', [ProfileController::class, 'update'])->name('account.update');
    Route::post('account/password', [ProfileController::class, 'password'])->name('account.password');
    Route::delete('account/tokens', [ProfileController::class, 'revokeTokens'])->name('account.tokens');
    Route::post('account/avatar', [ProfileController::class, 'avatar'])->name('account.avatar');
    Route::delete('account/avatar', [ProfileController::class, 'avatarRemove'])->name('account.avatar.remove');
});

// Password reset links. The token in the URL is the credential, so these are open
// to anonymous visitors; the page itself refuses unknown/expired/spent tokens.
// Rate limited because a link is a bearer token for somebody's account.
Route::get('password/reset/{token}', [PasswordResetController::class, 'show'])
    ->middleware('throttle:30,1')
    ->name('password.reset');
Route::post('password/reset/{token}', [PasswordResetController::class, 'update'])
    ->middleware('throttle:10,1')
    ->name('password.reset.update');

/*
|--------------------------------------------------------------------------
| Administration
|--------------------------------------------------------------------------
| Users with role super_admin only (AuthenticateAdmin).
*/
Route::prefix('admin')->name('admin.')->group(function () {
    Route::get('login', [AuthController::class, 'show'])->name('login');

    Route::middleware('admin')->group(function () {
        Route::post('logout', [AuthController::class, 'destroy'])->name('logout');

        Route::get('/', DashboardController::class)->name('dashboard');

        Route::get('users', [UserController::class, 'index'])->name('users.index');
        Route::post('users', [UserController::class, 'store'])->name('users.store');
        // Old addresses still in bookmarks: the list opens the "new user" dialog.
        Route::get('users/create', [UserController::class, 'create'])->name('users.create');
        Route::get('users/{user}', [UserController::class, 'show'])->name('users.show');
        Route::get('users/{user}/edit', [UserController::class, 'edit'])->name('users.edit');
        Route::put('users/{user}', [UserController::class, 'update'])->name('users.update');
        Route::delete('users/{user}', [UserController::class, 'destroy'])->name('users.destroy');
        Route::post('users/{user}/role', [UserController::class, 'role'])->name('users.role');
        Route::post('users/{user}/status', [UserController::class, 'status'])->name('users.status');
        Route::post('users/{user}/password', [UserController::class, 'resetPassword'])->name('users.password');
        Route::post('users/{user}/reset-link', [UserController::class, 'resetLink'])->name('users.reset-link');
        Route::post('users/{user}/avatar', [UserController::class, 'avatar'])->name('users.avatar');
        Route::delete('users/{user}/avatar', [UserController::class, 'avatarRemove'])->name('users.avatar.remove');
        Route::post('users/{user}/sign-out', [UserController::class, 'signOut'])->name('users.sign-out');

        Route::get('clients', [ClientController::class, 'index'])->name('clients.index');
        Route::get('clients/create', [ClientController::class, 'create'])->name('clients.create');
        Route::post('clients', [ClientController::class, 'store'])->name('clients.store');
        Route::get('clients/{client}/edit', [ClientController::class, 'edit'])->name('clients.edit');
        Route::put('clients/{client}', [ClientController::class, 'update'])->name('clients.update');

        Route::get('audit', [DashboardController::class, 'audit'])->name('audit.index');

    });
});
