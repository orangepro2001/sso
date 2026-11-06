<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Services\UserAccounts;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Illuminate\Http\Response;
use Illuminate\Validation\Rule;

/**
 * /api/users — account administration for super administrators, the same
 * operations as the console (UserAccounts holds the rules for both).
 */
class UserController extends Controller
{
    public function __construct(private readonly UserAccounts $accounts) {}

    public function index(Request $request): AnonymousResourceCollection
    {
        $filters = $request->validate([
            'q' => ['nullable', 'string', 'max:120'],
            'role' => ['nullable', Rule::in(User::ROLES)],
            'status' => ['nullable', Rule::in([User::STATUS_ACTIVE, User::STATUS_DISABLED])],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:200'],
        ]);

        $users = User::query()
            ->search($filters['q'] ?? null)
            ->when($filters['role'] ?? null, fn ($q, $role) => $q->where('role', $role))
            ->when($filters['status'] ?? null, fn ($q, $status) => $q->where('status', $status))
            ->orderBy('name')
            ->paginate((int) ($filters['per_page'] ?? 50))
            ->withQueryString();

        return UserResource::collection($users);
    }

    public function show(User $user): UserResource
    {
        return new UserResource($user);
    }

    public function store(Request $request): JsonResponse
    {
        UserAccounts::normaliseUsername($request);
        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => UserAccounts::usernameRules(),
            'password' => ['nullable', 'string'],
            'role' => ['nullable', Rule::in(User::ROLES)],
            'note' => ['nullable', 'string', 'max:2000'],
        ]);

        [$user, $generated] = $this->accounts->create($data, $request->user(), $request);

        $body = (new UserResource($user))->resolve($request);
        if ($generated !== null) {
            // The only copy of the plaintext; the caller shows it once.
            $body['generated_password'] = $generated;
        }

        return response()->json($body, 201);
    }

    public function update(Request $request, User $user): UserResource
    {
        UserAccounts::normaliseUsername($request);
        $data = $request->validate([
            'name' => ['sometimes', 'required', 'string', 'max:120'],
            'username' => ['sometimes', ...UserAccounts::usernameRules($user->id)],
            'role' => ['sometimes', 'required', Rule::in(User::ROLES)],
            'status' => ['sometimes', 'required', Rule::in([User::STATUS_ACTIVE, User::STATUS_DISABLED])],
            'note' => ['sometimes', 'nullable', 'string', 'max:2000'],
        ]);

        return new UserResource($this->accounts->update($user, $data, $request->user(), $request));
    }

    public function password(Request $request, User $user): JsonResponse
    {
        $data = $request->validate(['password' => ['nullable', 'string']]);
        $plain = $this->accounts->setPassword($user, $data['password'] ?? null, $request->user(), $request);

        return response()->json(['password' => $plain]);
    }

    public function resetLink(Request $request, User $user): JsonResponse
    {
        $link = $this->accounts->resetLink($user, $request->user(), $request);

        return response()->json(['url' => $link['url'], 'expires_at' => $link['expires_at']->toIso8601String()]);
    }

    public function avatar(Request $request, User $user): UserResource
    {
        $request->validate(['avatar' => UserAccounts::AVATAR_RULES]);
        $this->accounts->storeAvatar($user, $request->file('avatar'), $request->user(), $request);

        return new UserResource($user->fresh());
    }

    public function avatarRemove(Request $request, User $user): UserResource
    {
        $this->accounts->removeAvatar($user, $request->user(), $request);

        return new UserResource($user->fresh());
    }

    public function signOut(Request $request, User $user): JsonResponse
    {
        return response()->json($this->accounts->signOutEverywhere($user, $request->user(), $request));
    }

    public function destroy(Request $request, User $user): Response
    {
        $this->accounts->delete($user, $request->user(), $request);

        return response()->noContent();
    }
}
