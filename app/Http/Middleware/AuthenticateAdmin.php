<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * The console is for users whose role is `super_admin`. There is one sign-in (the
 * user one); this only checks the role and then exposes the user through the
 * `admin` guard, which is what the console controllers read for audit and
 * `created_by`.
 */
class AuthenticateAdmin
{
    public function handle(Request $request, Closure $next): Response
    {
        /** @var User|null $user */
        $user = Auth::guard('web')->user();

        if ($user === null) {
            return redirect()->guest(route('login'));
        }

        if (! $user->isActive() || ! $user->isSuperAdmin()) {
            abort(403, 'The console is for super administrators.');
        }

        Auth::guard('admin')->setUser($user);

        return $next($request);
    }
}
