<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * The console has no sign-in of its own any more: old /admin/login links go to the
 * user sign-in and come back to the console afterwards.
 */
class AuthController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function show(Request $request): RedirectResponse
    {
        $request->session()->put('url.intended', route('admin.dashboard'));

        return redirect()->route('login');
    }

    public function destroy(Request $request): RedirectResponse
    {
        $user = Auth::guard('web')->user();
        $this->audit->log('user.logout', 'user', $user?->id, 'user', $user?->id, [], $request);

        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('home');
    }
}
