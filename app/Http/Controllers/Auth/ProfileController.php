<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\AccessToken;
use App\Models\User;
use App\Services\AuditLogger;
use App\Services\PasswordResetService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Illuminate\View\View;

/**
 * The profile a normal user owns.
 *
 * Until now the only way to change a display name was to ask an administrator, which
 * is a strange thing to require of somebody's own name. What stays administrator-only
 * is anything that changes *who the account is*: the username (it is what other
 * applications match on), the status, and deleting anything.
 */
class ProfileController extends Controller
{
    public function __construct(
        private readonly PasswordResetService $resets,
        private readonly AuditLogger $audit,
    ) {}

    public function show(Request $request): View
    {
        $user = $request->user('web');

        return view('auth.account', [
            'user' => $user,
            'signedIn' => AccessToken::query()
                ->where('user_id', $user->id)
                ->whereNull('revoked_at')
                ->where(fn ($q) => $q->whereNull('expires_at')->orWhere('expires_at', '>', now()))
                ->latest('id')
                ->limit(10)
                ->get(),
        ]);
    }

    public function update(Request $request): RedirectResponse
    {
        $user = $request->user('web');

        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => [
                'required', 'string', 'min:3', 'max:64',
                'regex:'.User::USERNAME_PATTERN,
                Rule::unique('users', 'username')->ignore($user->id),
            ],
        ]);

        $usernameChanged = strtolower(trim($data['username'])) !== $user->username;

        // Changing what you sign in with is an identity event, so it needs the
        // password to prove it is the account holder and not a borrowed browser.
        $request->validate([
            'current_password' => [$usernameChanged ? 'required' : 'nullable', 'string'],
        ]);

        if ($usernameChanged && ! Hash::check((string) $request->input('current_password'), $user->password)) {
            return back()->withErrors(['current_password' => 'Changing your username needs your current password.']);
        }

        $before = ['name' => $user->name, 'username' => $user->username];

        $user->forceFill([
            'name' => trim($data['name']),
            'username' => strtolower(trim($data['username'])),
        ])->save();

        $this->audit->log('user.profile.updated', 'user', $user->id, 'user', $user->id, [
            'from' => $before,
            'to' => ['name' => $user->name, 'username' => $user->username],
        ], $request);

        return back()->with('status', $usernameChanged ? 'Profile updated. Use your new username next time.' : 'Name updated.');
    }

    /** Replace the profile picture; the old file is removed, not archived. */
    public function avatar(Request $request): RedirectResponse
    {
        $user = $request->user('web');

        $request->validate([
            'avatar' => ['required', 'file', 'mimetypes:image/jpeg,image/png,image/webp,image/gif', 'max:512'],
        ]);

        $file = $request->file('avatar');
        $extension = match ($file->getMimeType()) {
            'image/png' => 'png',
            'image/webp' => 'webp',
            'image/gif' => 'gif',
            default => 'jpg',
        };

        $path = 'avatars/'.$user->id.'/'.now()->format('YmdHis').'.'.$extension;
        Storage::disk('local')->put($path, $file->get());

        if ($user->avatar_path !== null) {
            Storage::disk('local')->delete($user->avatar_path);
        }

        $user->forceFill([
            'avatar_path' => $path,
            'avatar_mime' => $file->getMimeType(),
            'avatar_updated_at' => now(),
        ])->save();

        $this->audit->log('user.avatar.updated', 'user', $user->id, 'user', $user->id, ['path' => $path], $request);

        return back()->with('status', 'Picture updated.');
    }

    public function avatarRemove(Request $request): RedirectResponse
    {
        $user = $request->user('web');

        if ($user->avatar_path !== null) {
            Storage::disk('local')->delete($user->avatar_path);
            $user->forceFill(['avatar_path' => null, 'avatar_mime' => null, 'avatar_updated_at' => null])->save();

            $this->audit->log('user.avatar.removed', 'user', $user->id, 'user', $user->id, [], $request);
        }

        return back()->with('status', 'Picture removed.');
    }

    public function password(Request $request): RedirectResponse
    {
        $user = $request->user('web');

        $data = $request->validate([
            'current_password' => ['required', 'string'],
            'password' => ['required', 'string', Password::min(12), 'confirmed', 'different:current_password'],
        ]);

        if (! Hash::check($data['current_password'], $user->password)) {
            $this->audit->log('user.password.change_rejected', 'user', $user->id, 'user', $user->id, [], $request);

            return back()->withErrors(['current_password' => 'That is not your current password.']);
        }

        $user->forceFill(['password' => $data['password']])->save();

        // Same rule as an administrator-issued reset: the old password stops opening
        // things, so every token it produced is revoked. The browser session survives,
        // which is deliberate — you just proved you are the person at the keyboard.
        $revoked = $this->resets->revokeCredentials($user);

        $this->audit->log('user.password.changed', 'user', $user->id, 'user', $user->id, [
            'revoked' => $revoked,
        ], $request);

        return back()->with('status', 'Password changed. Other devices were signed out.');
    }

    /** Sign out everywhere: sessions stay (they are per-browser), tokens do not. */
    public function revokeTokens(Request $request): RedirectResponse
    {
        $user = $request->user('web');
        $revoked = $this->resets->revokeCredentials($user);

        $this->audit->log('user.tokens.revoked', 'user', $user->id, 'user', $user->id, $revoked, $request);

        return back()->with('status', 'Signed out of every application.');
    }

    public function destroy(Request $request): RedirectResponse
    {
        $user = $request->user('web');

        // Closing your own account is a support action, not a self-service one: other
        // applications may have data attached to the identity.
        return back()->withErrors([
            'account' => 'Ask an administrator to close your account.',
        ]);
    }
}
