<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Models\AccessToken;
use App\Models\User;
use App\Services\UserAccounts;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

/**
 * /api/me — the signed-in person's own account, for applications that want to let
 * people change their name or picture without leaving the application.
 *
 * The username is not changeable here: it is what applications match on, and a
 * change needs the password, which an application should never see.
 */
class MeController extends Controller
{
    public function __construct(private readonly UserAccounts $accounts) {}

    public function show(Request $request): UserResource
    {
        return new UserResource($request->user());
    }

    public function update(Request $request): UserResource
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
        ]);

        $user = $this->accounts->updateOwnProfile($request->user(), $data['name'], null, $request);

        return new UserResource($user);
    }

    public function avatar(Request $request): UserResource
    {
        $request->validate(['avatar' => UserAccounts::AVATAR_RULES]);

        /** @var User $user */
        $user = $request->user();
        $this->accounts->storeAvatar($user, $request->file('avatar'), $user, $request);

        return new UserResource($user->fresh());
    }

    public function avatarRemove(Request $request): UserResource
    {
        /** @var User $user */
        $user = $request->user();
        $this->accounts->removeAvatar($user, $user, $request);

        return new UserResource($user->fresh());
    }

    public function password(Request $request): JsonResponse
    {
        $data = $request->validate([
            'current_password' => ['required', 'string'],
            'password' => ['required', 'string', 'different:current_password'],
        ]);

        /** @var User $user */
        $user = $request->user();
        if (! Hash::check($data['current_password'], $user->password)) {
            throw ValidationException::withMessages(['current_password' => '현재 비밀번호가 맞지 않습니다.']);
        }

        /** @var AccessToken $token */
        $token = $request->attributes->get('access_token');
        $this->accounts->setPassword($user, $data['password'], $user, $request, keepJti: $token->jti);

        return response()->json(['message' => '비밀번호를 바꿨습니다. 다른 기기에서는 로그아웃됩니다.']);
    }
}
