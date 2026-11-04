<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

/**
 * End-user sign-in. This is the only way a user reaches /oauth/authorize;
 * accounts themselves can only be created by an administrator.
 */
class UserLoginController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function show(): View
    {
        return view('auth.login');
    }

    public function store(Request $request): RedirectResponse
    {
        $credentials = $request->validate([
            'username' => ['required', 'string', 'max:64'],
            'password' => ['required', 'string'],
        ]);

        // Usernames are stored lower-case; the lookup must not care about what the
        // person typed.
        $credentials['username'] = strtolower(trim($credentials['username']));

        $key = 'login:'.$credentials['username'].'|'.$request->ip();
        if (RateLimiter::tooManyAttempts($key, 10)) {
            throw ValidationException::withMessages([
                'username' => 'Too many attempts. Try again in '.RateLimiter::availableIn($key).' seconds.',
            ]);
        }

        $remember = $request->boolean('remember');

        if (! Auth::guard('web')->attempt($credentials, $remember)) {
            RateLimiter::hit($key, 300);
            $this->audit->log('login.failed', 'anonymous', $credentials['username'], 'user', $credentials['username'], [
                'guard' => 'web',
            ], $request);

            throw ValidationException::withMessages(['username' => 'These credentials do not match our records.']);
        }

        /** @var User $user */
        $user = Auth::guard('web')->user();
        if (! $user->isActive()) {
            Auth::guard('web')->logout();
            $this->audit->log('login.denied', 'user', $user->id, 'user', $user->id, ['reason' => 'disabled'], $request);

            throw ValidationException::withMessages(['username' => 'This account has been disabled.']);
        }

        RateLimiter::clear($key);
        $request->session()->regenerate();

        $user->forceFill([
            'last_login_at' => now(),
            'last_login_ip' => $this->audit->ip($request),
        ])->save();

        $this->audit->log('login.succeeded', 'user', $user->id, 'user', $user->id, ['guard' => 'web'], $request);

        // Resume an interrupted authorization request, if there is one.
        if ($request->session()->has('oauth.pending')) {
            return redirect()->route('oauth.authorize', $request->session()->get('oauth.pending'));
        }

        return redirect()->intended(route('home'));
    }

    public function destroy(Request $request): RedirectResponse
    {
        $user = Auth::guard('web')->user();
        $this->audit->log('logout', 'user', $user?->id, 'user', $user?->id, ['guard' => 'web'], $request);

        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('home');
    }
}
