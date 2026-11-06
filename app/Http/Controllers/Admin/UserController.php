<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AccessToken;
use App\Models\AuditLog;
use App\Models\User;
use App\Services\UserAccounts;
use App\Support\AuditPresenter;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

/**
 * The console's centre: the people. One list, one page per person, and every
 * action on that page is a single button (UserAccounts holds the rules).
 */
class UserController extends Controller
{
    public function __construct(private readonly UserAccounts $accounts) {}

    public function index(Request $request): View
    {
        $search = trim((string) $request->query('q', ''));
        $filter = (string) $request->query('filter', 'all');

        $users = User::query()
            ->search($search)
            ->when($filter === 'admin', fn ($q) => $q->where('role', User::ROLE_SUPER_ADMIN))
            ->when($filter === 'user', fn ($q) => $q->where('role', User::ROLE_USER))
            ->when($filter === 'disabled', fn ($q) => $q->where('status', User::STATUS_DISABLED))
            // Disabled accounts sink; within a group the person most recently
            // active comes first, which is who an administrator usually looks for.
            ->orderByRaw('case when status = ? then 0 else 1 end', [User::STATUS_ACTIVE])
            ->orderByRaw('last_login_at desc nulls last')
            ->orderBy('name')
            ->paginate(50)
            ->withQueryString();

        return view('admin.users.index', [
            'users' => $users,
            'search' => $search,
            'filter' => $filter,
            'counts' => [
                'all' => User::query()->count(),
                'admin' => User::query()->where('role', User::ROLE_SUPER_ADMIN)->count(),
                'user' => User::query()->where('role', User::ROLE_USER)->count(),
                'disabled' => User::query()->where('status', User::STATUS_DISABLED)->count(),
            ],
        ]);
    }

    /** Old bookmark: the list with the "new user" dialog open. */
    public function create(): RedirectResponse
    {
        return redirect()->route('admin.users.index', ['new' => 1]);
    }

    /** Old bookmark: the edit form is now part of the person's page. */
    public function edit(User $user): RedirectResponse
    {
        return redirect()->route('admin.users.show', $user);
    }

    public function store(Request $request): RedirectResponse
    {
        UserAccounts::normaliseUsername($request);

        $data = $request->validateWithBag('create', [
            'name' => ['required', 'string', 'max:120'],
            'username' => UserAccounts::usernameRules(),
            'password' => ['nullable', 'string'],
            'role' => ['nullable', Rule::in(User::ROLES)],
            'note' => ['nullable', 'string', 'max:2000'],
        ]);

        [$user, $generated] = $this->accounts->create($data, $this->actor(), $request);

        return redirect()->route('admin.users.show', $user)
            ->with('status', "{$user->name} ({$user->username}) 계정을 만들었습니다.")
            // The only moment the plaintext exists: shown once on the next page.
            ->with('generated_password', $generated === null ? null : [$user->username => $generated]);
    }

    public function show(User $user): View
    {
        $activity = AuditLog::query()
            ->where(fn ($q) => $q
                ->where(fn ($w) => $w->where('subject_type', 'user')->where('subject_id', (string) $user->id))
                ->orWhere(fn ($w) => $w->whereIn('actor_type', ['user', 'admin'])->where('actor_id', (string) $user->id)))
            ->latest('id')
            ->limit(12)
            ->get();

        return view('admin.users.show', [
            'user' => $user->load('creator'),
            'self' => $user->id === $this->actor()->id,
            'tokens' => AccessToken::query()
                ->with('client')
                ->where('user_id', $user->id)
                ->whereNull('revoked_at')
                ->where(fn ($q) => $q->whereNull('expires_at')->orWhere('expires_at', '>', now()))
                ->latest('id')
                ->limit(20)
                ->get(),
            'activity' => $activity,
            'people' => AuditPresenter::people($activity),
        ]);
    }

    public function update(Request $request, User $user): RedirectResponse
    {
        UserAccounts::normaliseUsername($request);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'username' => UserAccounts::usernameRules($user->id),
            'note' => ['nullable', 'string', 'max:2000'],
        ]);

        $this->accounts->update($user, $data, $this->actor(), $request);

        return back()->with('status', '기본 정보를 저장했습니다.');
    }

    public function role(Request $request, User $user): RedirectResponse
    {
        $data = $request->validate(['role' => ['required', Rule::in(User::ROLES)]]);
        $this->accounts->update($user, $data, $this->actor(), $request);

        return back()->with('status', $user->isSuperAdmin()
            ? "{$user->name} 님을 관리자로 지정했습니다."
            : "{$user->name} 님을 일반 사용자로 바꿨습니다.");
    }

    public function status(Request $request, User $user): RedirectResponse
    {
        $data = $request->validate(['status' => ['required', Rule::in([User::STATUS_ACTIVE, User::STATUS_DISABLED])]]);
        $this->accounts->update($user, $data, $this->actor(), $request);

        return back()->with('status', $user->isActive()
            ? "{$user->name} 님의 계정을 다시 활성화했습니다."
            : "{$user->name} 님의 계정을 비활성화했습니다. 모든 앱과 브라우저에서 로그아웃됩니다.");
    }

    public function resetPassword(Request $request, User $user): RedirectResponse
    {
        $data = $request->validate(['password' => ['nullable', 'string']]);
        $plain = $this->accounts->setPassword($user, $data['password'] ?? null, $this->actor(), $request);

        return redirect()->route('admin.users.show', $user)
            ->with('status', '비밀번호를 설정했습니다. 이 사용자는 모든 앱에서 로그아웃됩니다.')
            ->with('generated_password', [$user->username => $plain]);
    }

    public function resetLink(Request $request, User $user): RedirectResponse
    {
        $link = $this->accounts->resetLink($user, $this->actor(), $request);

        return redirect()->route('admin.users.show', $user)
            ->with('status', '비밀번호 재설정 링크를 만들었습니다.')
            ->with('reset_url', $link['url'])
            ->with('reset_expires', $link['expires_at']->format('Y-m-d H:i'));
    }

    public function avatar(Request $request, User $user): RedirectResponse
    {
        $request->validate(['avatar' => UserAccounts::AVATAR_RULES]);
        $this->accounts->storeAvatar($user, $request->file('avatar'), $this->actor(), $request);

        return back()->with('status', '프로필 사진을 바꿨습니다.');
    }

    public function avatarRemove(Request $request, User $user): RedirectResponse
    {
        $this->accounts->removeAvatar($user, $this->actor(), $request);

        return back()->with('status', '프로필 사진을 지웠습니다.');
    }

    public function signOut(Request $request, User $user): RedirectResponse
    {
        $counts = $this->accounts->signOutEverywhere($user, $this->actor(), $request);

        return back()->with('status', "모든 곳에서 로그아웃시켰습니다 (앱 토큰 {$counts['access_tokens']}개, 브라우저 세션 {$counts['sessions']}개).");
    }

    public function destroy(Request $request, User $user): RedirectResponse
    {
        $request->validate(['confirm' => ['required', 'string', Rule::in([$user->username])]], [
            'confirm.in' => '확인란에 아이디를 정확히 입력하세요.',
            'confirm.required' => '확인란에 아이디를 입력하세요.',
        ]);

        $this->accounts->delete($user, $this->actor(), $request);

        return redirect()->route('admin.users.index')->with('status', "{$user->name} ({$user->username}) 계정을 삭제했습니다.");
    }

    private function actor(): User
    {
        /** @var User */
        return Auth::guard('admin')->user();
    }
}
