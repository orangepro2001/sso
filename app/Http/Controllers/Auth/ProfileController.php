<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\AccessToken;
use App\Models\User;
use App\Services\UserAccounts;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\View\View;

/**
 * The account a person owns: name, picture, password, where they are signed in.
 *
 * The username can change too, but only with the current password: it is what a
 * person signs in with, and a borrowed browser must not be able to rename the
 * account under its owner.
 */
class ProfileController extends Controller
{
    public function __construct(private readonly UserAccounts $accounts) {}

    public function show(Request $request): View
    {
        $user = $request->user('web');

        return view('auth.account', [
            'user' => $user,
            'signedIn' => AccessToken::query()
                ->with('client')
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
        /** @var User $user */
        $user = $request->user('web');
        UserAccounts::normaliseUsername($request);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => ['sometimes', ...UserAccounts::usernameRules($user->id)],
        ]);

        $username = $data['username'] ?? $user->username;
        $usernameChanged = $username !== $user->username;

        if ($usernameChanged && ! Hash::check((string) $request->input('current_password'), $user->password)) {
            return back()->withInput()->withErrors(['current_password' => '아이디를 바꾸려면 현재 비밀번호를 입력하세요.']);
        }

        $this->accounts->updateOwnProfile($user, $data['name'], $username, $request);

        return back()->with('status', $usernameChanged ? '저장했습니다. 다음 로그인부터 새 아이디를 쓰세요.' : '저장했습니다.');
    }

    public function avatar(Request $request): RedirectResponse
    {
        $request->validate(['avatar' => UserAccounts::AVATAR_RULES]);

        $user = $request->user('web');
        $this->accounts->storeAvatar($user, $request->file('avatar'), $user, $request);

        return back()->with('status', '프로필 사진을 바꿨습니다.');
    }

    public function avatarRemove(Request $request): RedirectResponse
    {
        $user = $request->user('web');
        $this->accounts->removeAvatar($user, $user, $request);

        return back()->with('status', '프로필 사진을 지웠습니다.');
    }

    public function password(Request $request): RedirectResponse
    {
        /** @var User $user */
        $user = $request->user('web');

        $data = $request->validate([
            'current_password' => ['required', 'string'],
            'password' => ['required', 'string', 'confirmed', 'different:current_password'],
        ]);

        if (! Hash::check($data['current_password'], $user->password)) {
            return back()->withErrors(['current_password' => '현재 비밀번호가 맞지 않습니다.']);
        }

        // Every token the old password produced is revoked. This browser stays
        // signed in: the person at the keyboard just proved who they are.
        $this->accounts->setPassword($user, $data['password'], $user, $request);

        return back()->with('status', '비밀번호를 바꿨습니다. 다른 기기와 앱에서는 로그아웃됩니다.');
    }

    /** Sign out of every application and every other browser. */
    public function revokeTokens(Request $request): RedirectResponse
    {
        $user = $request->user('web');
        $this->accounts->signOutEverywhere($user, $user, $request);

        return back()->with('status', '모든 앱과 다른 브라우저에서 로그아웃했습니다.');
    }
}
