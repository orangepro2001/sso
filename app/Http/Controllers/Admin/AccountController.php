<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Admin;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;
use Illuminate\View\View;

/**
 * Self-service password change for the signed-in administrator.
 *
 * Requires the current password (a stolen session must not be enough to lock the
 * real owner out) and re-issues the session id afterwards.
 */
class AccountController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function edit(): View
    {
        return view('admin.account');
    }

    public function updatePassword(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'current_password' => ['required', 'string'],
            'password' => ['required', 'string', 'confirmed', Password::min(12)],
        ]);

        /** @var Admin $admin */
        $admin = Auth::guard('admin')->user();

        if (! Hash::check($data['current_password'], $admin->password)) {
            $this->audit->log('admin.password_change.failed', 'admin', $admin->id, 'admin', $admin->id, [], $request);

            throw ValidationException::withMessages(['current_password' => 'The current password is incorrect.']);
        }

        $admin->forceFill(['password' => Hash::make($data['password'])])->save();

        // A new session id invalidates anything that was fixed on the old one.
        $request->session()->regenerate();

        $this->audit->log('admin.password_changed', 'admin', $admin->id, 'admin', $admin->id, [], $request);

        return redirect()->route('admin.account')->with('status', 'Password changed.');
    }

    public function updateName(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
        ]);

        $admin = Auth::guard('admin')->user();
        $admin->forceFill(['name' => $data['name']])->save();

        $this->audit->log('admin.profile_updated', 'admin', $admin->id, 'admin', $admin->id, [], $request);

        return redirect()->route('admin.account')->with('status', 'Profile updated.');
    }
}
