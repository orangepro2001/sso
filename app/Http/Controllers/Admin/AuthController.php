<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

class AuthController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function show(): View
    {
        return view('admin.login');
    }

    public function store(Request $request): RedirectResponse
    {
        $credentials = $request->validate([
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        $key = 'admin-login:'.strtolower($credentials['email']).'|'.$request->ip();
        if (RateLimiter::tooManyAttempts($key, 5)) {
            throw ValidationException::withMessages([
                'email' => 'Too many attempts. Try again in '.RateLimiter::availableIn($key).' seconds.',
            ]);
        }

        if (! Auth::guard('admin')->attempt($credentials, $request->boolean('remember'))) {
            RateLimiter::hit($key, 300);
            $this->audit->log('admin.login.failed', 'anonymous', $credentials['email'], 'admin', $credentials['email'], [], $request);

            throw ValidationException::withMessages(['email' => 'These credentials do not match our records.']);
        }

        if (! Auth::guard('admin')->user()->active) {
            Auth::guard('admin')->logout();
            throw ValidationException::withMessages(['email' => 'This administrator account is disabled.']);
        }

        RateLimiter::clear($key);
        $request->session()->regenerate();

        $admin = Auth::guard('admin')->user();
        $admin->forceFill([
            'last_login_at' => now(),
            'last_login_ip' => $this->audit->ip($request),
        ])->save();

        $this->audit->log('admin.login.succeeded', 'admin', $admin->id, 'admin', $admin->id, [], $request);

        return redirect()->intended(route('admin.dashboard'));
    }

    public function destroy(Request $request): RedirectResponse
    {
        $admin = Auth::guard('admin')->user();
        $this->audit->log('admin.logout', 'admin', $admin?->id, 'admin', $admin?->id, [], $request);

        Auth::guard('admin')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('admin.login');
    }
}
