<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogger;
use App\Services\RegistrationInviteService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Illuminate\View\View;

/**
 * Self-registration, but only with a code an administrator issued.
 *
 * The application still has no public sign-up: the URL is the credential, it is
 * single use, it expires, and it dies when the administrator revokes it. What this
 * buys is onboarding without an administrator inventing somebody's password and
 * reading it out loud.
 */
class RegistrationController extends Controller
{
    public function __construct(
        private readonly RegistrationInviteService $invites,
        private readonly AuditLogger $audit,
    ) {}

    public function show(string $code): View
    {
        $invite = $this->invites->find($code);

        return view('auth.register', [
            'invalid' => $invite === null || ! $invite->isUsable(),
            'code' => $code,
            'note' => $invite?->note,
        ]);
    }

    public function store(Request $request, string $code): RedirectResponse|View
    {
        $invite = $this->invites->find($code);

        if ($invite === null || ! $invite->isUsable()) {
            $this->audit->log('user.register.rejected', 'anonymous', null, 'invite', $this->fingerprint($code), [
                'reason' => $invite === null ? 'unknown' : $invite->reason(),
            ], $request);

            return view('auth.register', [
                'invalid' => true,
                'code' => $code,
                'note' => null,
            ]);
        }

        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => [
                'required', 'string', 'min:3', 'max:64',
                'regex:'.User::USERNAME_PATTERN,
                Rule::unique('users', 'username'),
            ],
            'password' => ['required', 'string', Password::min(12), 'confirmed'],
        ]);

        $user = DB::transaction(function () use ($invite, $data, $request) {
            $user = User::create([
                'name' => $data['name'],
                'username' => $data['username'],
                'password' => $data['password'],
                'status' => User::STATUS_ACTIVE,
                'created_by' => $invite->created_by,
                'note' => 'self-registered with an invite',
            ]);

            $invite->forceFill([
                'used_at' => now(),
                'used_ip' => $request->ip(),
                'used_by' => $user->id,
            ])->save();

            return $user;
        });

        $this->audit->log('user.register', 'user', $user->id, 'invite', $invite->id, [
            'username' => $user->username,
        ], $request);

        Auth::guard('web')->login($user);
        $request->session()->regenerate();

        // Same continuation as a normal sign-in: finish the authorization that sent
        // the person here, otherwise land on the account page.
        $pending = $request->session()->get('oauth.pending');

        return $pending
            ? redirect()->route('oauth.authorize', $pending)
            : redirect()->route('home');
    }

    /**
     * Codes never appear in logs: only a short fingerprint that can be correlated
     * with the row, not replayed.
     */
    private function fingerprint(string $code): string
    {
        return substr(hash('sha256', $code), 0, 16);
    }
}
