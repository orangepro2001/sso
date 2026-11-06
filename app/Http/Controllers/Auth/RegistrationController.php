<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

/**
 * Open self-registration: display name, username, password. A new account gets the
 * plain `user` role; a super administrator can promote it in the console.
 */
class RegistrationController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function show(): View
    {
        return view('auth.register');
    }

    public function store(Request $request): RedirectResponse
    {
        $username = $request->input('username');
        if (is_string($username)) {
            $request->merge(['username' => strtolower(trim($username))]);
        }

        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => [
                'required', 'string', 'min:3', 'max:64',
                'regex:'.User::USERNAME_PATTERN,
                Rule::unique('users', 'username'),
            ],
            'password' => ['required', 'string', 'confirmed'],
        ]);

        $user = User::create([
            'name' => $data['name'],
            'username' => $data['username'],
            'password' => $data['password'],
            'role' => User::ROLE_USER,
            'status' => User::STATUS_ACTIVE,
            'note' => 'self-registered',
        ]);

        $this->audit->log('user.register', 'user', $user->id, 'user', $user->id, [
            'username' => $user->username,
        ], $request);

        Auth::guard('web')->login($user);
        $request->session()->regenerate();

        // Same continuation as a normal sign-in: finish the authorization that sent
        // the person here, otherwise land on the home page.
        $pending = $request->session()->get('oauth.pending');

        return $pending
            ? redirect()->route('oauth.authorize', $pending)
            : redirect()->route('home');
    }
}
