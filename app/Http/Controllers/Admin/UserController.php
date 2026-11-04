<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Illuminate\View\View;

/**
 * Account administration. There is no self-service registration: every user row
 * originates from this controller.
 */
class UserController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function index(Request $request): View
    {
        $search = trim((string) $request->query('q', ''));

        $users = User::query()
            ->when($search !== '', fn ($q) => $q->where(fn ($w) => $w
                ->where('username', 'ilike', '%'.$search.'%')
                ->orWhere('name', 'ilike', '%'.$search.'%')))
            ->latest('id')
            ->paginate(25)
            ->withQueryString();

        return view('admin.users.index', ['users' => $users, 'search' => $search]);
    }

    public function create(): View
    {
        return view('admin.users.create', ['suggestedPassword' => Str::password(16)]);
    }

    public function store(Request $request): RedirectResponse
    {
        $this->normaliseUsername($request);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => $this->usernameRules(),
            'password' => ['required', 'string', Password::min(12)],
            'note' => ['nullable', 'string', 'max:2000'],
        ]);

        $user = User::create([
            'name' => $data['name'],
            'username' => $data['username'],
            'password' => $data['password'],
            'status' => User::STATUS_ACTIVE,
            'note' => $data['note'] ?? null,
            'created_by' => Auth::guard('admin')->id(),
        ]);

        $this->audit->log('admin.user.created', 'admin', Auth::guard('admin')->id(), 'user', $user->id, [
            'username' => $user->username,
        ], $request);

        return redirect()->route('admin.users.index')
            ->with('status', "User {$user->username} created.");
    }

    public function edit(User $user): View
    {
        return view('admin.users.edit', ['user' => $user]);
    }

    public function update(Request $request, User $user): RedirectResponse
    {
        $this->normaliseUsername($request);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => $this->usernameRules($user->id),
            'status' => ['required', Rule::in([User::STATUS_ACTIVE, User::STATUS_DISABLED])],
            'note' => ['nullable', 'string', 'max:2000'],
        ]);

        $user->fill($data)->save();

        $this->audit->log('admin.user.updated', 'admin', Auth::guard('admin')->id(), 'user', $user->id, [
            'username' => $user->username, 'status' => $user->status,
        ], $request);

        return redirect()->route('admin.users.index')->with('status', "User {$user->username} updated.");
    }

    public function resetPassword(Request $request, User $user): RedirectResponse
    {
        $data = $request->validate([
            'password' => ['required', 'string', Password::min(12)],
        ]);

        $user->forceFill(['password' => $data['password']])->save();

        $this->audit->log('admin.user.password_reset', 'admin', Auth::guard('admin')->id(), 'user', $user->id, [
            'username' => $user->username,
        ], $request);

        return redirect()->route('admin.users.edit', $user)->with('status', 'Password replaced.');
    }

    /**
     * Lower-case the username before validating it, so that what the administrator
     * typed is checked (and echoed back on error) in the same shape it is stored.
     * Without this, "MiXeD.Case" is rejected by the lower-case-only pattern even
     * though it is a perfectly good username.
     */
    private function normaliseUsername(Request $request): void
    {
        $value = $request->input('username');
        if (is_string($value)) {
            $request->merge(['username' => strtolower(trim($value))]);
        }
    }

    /**
     * Usernames are the login identifier, so they are constrained tightly: ASCII,
     * lower-case, no leading/trailing punctuation, unique.
     *
     * @return array<int, mixed>
     */
    private function usernameRules(?int $ignoreId = null): array
    {
        $unique = Rule::unique('users', 'username');
        if ($ignoreId !== null) {
            $unique->ignore($ignoreId);
        }

        return [
            'required',
            'string',
            'min:3',
            'max:64',
            'regex:'.User::USERNAME_PATTERN,
            $unique,
        ];
    }
}
