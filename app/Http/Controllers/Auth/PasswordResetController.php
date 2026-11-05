<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\UserPasswordReset;
use App\Services\AuditLogger;
use App\Services\PasswordResetService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;
use Illuminate\View\View;

/**
 * The page a reset link points at.
 *
 * Unauthenticated by design: the link itself is the credential. It is single use,
 * expires, and dies as soon as it has been used or superseded.
 */
class PasswordResetController extends Controller
{
    public function __construct(
        private readonly PasswordResetService $resets,
        private readonly AuditLogger $audit,
    ) {}

    public function show(Request $request, string $token): View
    {
        $reset = $this->resets->find($token);

        if ($reset === null || ! $reset->isUsable()) {
            $this->audit->log('user.password_reset.rejected', 'anonymous', null, 'reset_link', $this->fingerprint($token), [
                'reason' => $reset === null ? 'unknown' : $this->reason($reset),
            ], $request);

            return view('auth.reset', ['invalid' => true, 'token' => null, 'user' => null]);
        }

        return view('auth.reset', [
            'invalid' => false,
            'token' => $token,
            'user' => $reset->user,
        ]);
    }

    public function update(Request $request, string $token): RedirectResponse|View
    {
        $reset = $this->resets->find($token);

        if ($reset === null || ! $reset->isUsable()) {
            $this->audit->log('user.password_reset.rejected', 'anonymous', null, 'reset_link', $this->fingerprint($token), [
                'reason' => $reset === null ? 'unknown' : $this->reason($reset),
            ], $request);

            return view('auth.reset', ['invalid' => true, 'token' => null, 'user' => null]);
        }

        $user = $reset->user;
        if ($user === null) {
            return view('auth.reset', ['invalid' => true, 'token' => null, 'user' => null]);
        }

        $data = $request->validate([
            'password' => ['required', 'string', 'confirmed', Password::min(12)],
        ]);

        $user->forceFill(['password' => Hash::make($data['password'])])->save();

        $this->resets->consume($reset, $request->ip());
        $revoked = $this->resets->revokeCredentials($user);

        $this->audit->log('user.password_reset.completed', 'user', $user->id, 'user', $user->id, [
            'username' => $user->username,
            'revoked' => $revoked,
        ], $request);

        return redirect()->route('login')->with('status', 'Password changed. Sign in with the new one.');
    }

    private function reason(UserPasswordReset $reset): string
    {
        if ($reset->used_at !== null) {
            return 'already used';
        }
        if ($reset->revoked_at !== null) {
            return 'superseded';
        }

        return 'expired';
    }

    /**
     * Audit rows must not contain a usable token, so only a short digest prefix is
     * recorded: enough to correlate two attempts, useless as a credential.
     */
    private function fingerprint(string $token): string
    {
        return substr(hash('sha256', $token), 0, 12);
    }
}
