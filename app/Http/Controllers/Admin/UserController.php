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
        // Deliberately no pre-filled password: a value rendered into the form is
        // only a suggestion, and a page that was refreshed or visited via the back
        // button shows a value that will not be stored. The password is either
        // typed by the administrator or generated on submit and shown once.
        return view('admin.users.create');
    }

    public function store(Request $request): RedirectResponse
    {
        $this->normaliseUsername($request);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => $this->usernameRules(),
            'password' => ['nullable', 'string', Password::min(12)],
            'note' => ['nullable', 'string', 'max:2000'],
        ]);

        // Blank means "you pick one": generate, then show it once on the next page.
        $plain = $this->passwordToStore($data['password'] ?? null);

        $user = User::create([
            'name' => $data['name'],
            'username' => $data['username'],
            'password' => $plain,
            'status' => User::STATUS_ACTIVE,
            'note' => $data['note'] ?? null,
            'created_by' => Auth::guard('admin')->id(),
        ]);

        $this->audit->log('admin.user.created', 'admin', Auth::guard('admin')->id(), 'user', $user->id, [
            'username' => $user->username,
        ], $request);

        return redirect()->route('admin.users.index')
            ->with('status', "User {$user->username} created.")
            // Shown exactly once, on the page the administrator lands on: this is
            // the only moment the plaintext exists.
            ->with('generated_password', [$user->username => $plain]);
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
            'password' => ['nullable', 'string', Password::min(12)],
        ]);

        $plain = $this->passwordToStore($data['password'] ?? null);

        $user->forceFill(['password' => $plain])->save();

        $this->audit->log('admin.user.password_reset', 'admin', Auth::guard('admin')->id(), 'user', $user->id, [
            'username' => $user->username,
        ], $request);

        return redirect()->route('admin.users.edit', $user)
            ->with('status', 'Password replaced.')
            ->with('generated_password', [$user->username => $plain]);
    }

    /**
     * The password that will actually be stored. An explicit value wins; a blank
     * one becomes a generated password which the caller must display to the
     * administrator, because that is the only copy that will ever exist.
     */
    private function passwordToStore(?string $typed): string
    {
        return $typed !== null && $typed !== '' ? $typed : Str::password(20, symbols: false);
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
