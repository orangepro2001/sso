<?php

namespace App\Http\Middleware;

use App\Models\Admin;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * The console is closed by default: no registration, only admins created by an
 * admin (or the bootstrap one from the environment) can log in.
 */
class AuthenticateAdmin
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! Auth::guard('admin')->check()) {
            return redirect()->guest(route('admin.login'));
        }

        /** @var Admin|null $admin */
        $admin = Auth::guard('admin')->user();
        if ($admin === null || ! $admin->active) {
            Auth::guard('admin')->logout();
            $request->session()->invalidate();

            return redirect()->route('admin.login')->withErrors(['email' => 'This administrator account is disabled.']);
        }

        return $next($request);
    }
}
