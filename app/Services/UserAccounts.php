<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

/**
 * Every change to an account, whoever asks for it: the console, the account page
 * and the JSON API all call this, so the rules and the audit trail are the same
 * whichever door the change came through.
 *
 * Two rules exist only here:
 *  - there is always at least one active super administrator, otherwise nobody can
 *    reach the console again;
 *  - an administrator cannot demote, disable or delete themselves (the same lock-out,
 *    one person at a time).
 */
class UserAccounts
{
    /** Pictures are resized in the browser first; this only stops abuse. */
    public const AVATAR_RULES = ['required', 'file', 'mimetypes:image/jpeg,image/png,image/webp,image/gif', 'max:1024'];

    public function __construct(
        private readonly AuditLogger $audit,
        private readonly PasswordResetService $resets,
    ) {}

    /**
     * @return array<int, mixed>
     */
    public static function usernameRules(?int $ignoreId = null): array
    {
        $unique = Rule::unique('users', 'username');
        if ($ignoreId !== null) {
            $unique->ignore($ignoreId);
        }

        return ['required', 'string', 'min:3', 'max:64', 'regex:'.User::USERNAME_PATTERN, $unique];
    }

    /**
     * Lower-case before validating, so the value is checked (and echoed back on an
     * error) in the shape it will be stored in.
     */
    public static function normaliseUsername(Request $request): void
    {
        $value = $request->input('username');
        if (is_string($value)) {
            $request->merge(['username' => strtolower(trim($value))]);
        }
    }

    /**
     * @param  array{name: string, username: string, password?: ?string, role?: ?string, note?: ?string}  $data
     * @return array{0: User, 1: string|null} the user, and the generated password if one was generated
     */
    public function create(array $data, User $actor, ?Request $request = null): array
    {
        $typed = $data['password'] ?? null;
        $plain = $this->passwordOrGenerated($typed);

        $user = User::create([
            'name' => trim($data['name']),
            'username' => $data['username'],
            'password' => $plain,
            'role' => $data['role'] ?? User::ROLE_USER,
            'status' => User::STATUS_ACTIVE,
            'note' => $data['note'] ?? null,
            'created_by' => $actor->id,
        ]);

        $this->audit->log('admin.user.created', 'admin', $actor->id, 'user', $user->id, [
            'username' => $user->username, 'role' => $user->role,
        ], $request);

        return [$user, $typed === null || $typed === '' ? $plain : null];
    }

    /**
     * Change any subset of name, username, note, role and status.
     *
     * @param  array<string, mixed>  $data
     */
    public function update(User $user, array $data, User $actor, ?Request $request = null): User
    {
        $changes = array_intersect_key($data, array_flip(['name', 'username', 'note', 'role', 'status']));
        if (isset($changes['name'])) {
            $changes['name'] = trim((string) $changes['name']);
        }

        $losesAdmin = $user->isSuperAdmin() && $user->isActive() && (
            (isset($changes['role']) && $changes['role'] !== User::ROLE_SUPER_ADMIN)
            || (isset($changes['status']) && $changes['status'] !== User::STATUS_ACTIVE)
        );

        if ($losesAdmin) {
            $this->guardAdminLoss($user, $actor, isset($changes['status']) && $changes['status'] !== User::STATUS_ACTIVE ? 'status' : 'role');
        }

        $before = $user->only(array_keys($changes));
        $user->fill($changes)->save();
        $after = $user->only(array_keys($changes));

        $diff = array_filter(array_keys($after), fn ($k) => ($before[$k] ?? null) !== $after[$k]);
        if ($diff === []) {
            return $user;
        }

        // A disabled account must stop working everywhere at once, not when its
        // seven-day token runs out or its browser session expires.
        if (in_array('status', $diff, true) && ! $user->isActive()) {
            $this->endEverySession($user);
        }

        $this->audit->log('admin.user.updated', 'admin', $actor->id, 'user', $user->id, [
            'username' => $user->username,
            'changed' => array_values($diff),
            'from' => array_intersect_key($before, array_flip($diff)),
            'to' => array_intersect_key($after, array_flip($diff)),
        ], $request);

        return $user;
    }

    /**
     * A person changing their own name (and, with their password, their username).
     */
    public function updateOwnProfile(User $user, string $name, ?string $username, ?Request $request = null): User
    {
        $before = ['name' => $user->name, 'username' => $user->username];

        $user->forceFill([
            'name' => trim($name),
            'username' => $username ?? $user->username,
        ])->save();

        $after = ['name' => $user->name, 'username' => $user->username];
        if ($before !== $after) {
            $this->audit->log('user.profile.updated', 'user', $user->id, 'user', $user->id, [
                'from' => $before, 'to' => $after,
            ], $request);
        }

        return $user;
    }

    /**
     * Set a password (blank = generate one) and end every credential the old one
     * produced. $keepJti spares the token making an API call, so a client that
     * changes the password is not signed out by its own request.
     *
     * @return string the password now in force, for showing once
     */
    public function setPassword(User $user, ?string $typed, User $actor, ?Request $request = null, ?string $keepJti = null): string
    {
        $plain = $this->passwordOrGenerated($typed);
        $user->forceFill(['password' => $plain])->save();

        $revoked = $this->resets->revokeCredentials($user, $keepJti);
        $self = $actor->id === $user->id;

        $this->audit->log(
            $self ? 'user.password.changed' : 'admin.user.password_reset',
            $self ? 'user' : 'admin', $actor->id, 'user', $user->id,
            ['username' => $user->username, 'revoked' => $revoked],
            $request,
        );

        return $plain;
    }

    /**
     * @return array{url: string, expires_at: Carbon}
     */
    public function resetLink(User $user, User $actor, ?Request $request = null): array
    {
        [$plain, $row] = $this->resets->issue($user, $actor->id);

        $this->audit->log('admin.user.reset_link_created', 'admin', $actor->id, 'user', $user->id, [
            'username' => $user->username,
            'expires_at' => $row->expires_at->toIso8601String(),
        ], $request);

        return ['url' => $this->resets->url($plain), 'expires_at' => $row->expires_at];
    }

    /** Replace the picture; the old file is removed, not archived. */
    public function storeAvatar(User $user, UploadedFile $file, User $actor, ?Request $request = null): void
    {
        $mime = (string) $file->getMimeType();
        $extension = match ($mime) {
            'image/png' => 'png',
            'image/webp' => 'webp',
            'image/gif' => 'gif',
            default => 'jpg',
        };

        $path = 'avatars/'.$user->id.'/'.now()->format('YmdHis').'-'.Str::lower(Str::random(6)).'.'.$extension;
        Storage::disk('local')->put($path, $file->get());

        if ($user->avatar_path !== null && $user->avatar_path !== $path) {
            Storage::disk('local')->delete($user->avatar_path);
        }

        $user->forceFill([
            'avatar_path' => $path,
            'avatar_mime' => $mime,
            'avatar_updated_at' => now(),
        ])->save();

        $self = $actor->id === $user->id;
        $this->audit->log($self ? 'user.avatar.updated' : 'admin.user.avatar_updated', $self ? 'user' : 'admin', $actor->id, 'user', $user->id, [
            'path' => $path,
        ], $request);
    }

    public function removeAvatar(User $user, User $actor, ?Request $request = null): void
    {
        if ($user->avatar_path === null) {
            return;
        }

        Storage::disk('local')->delete($user->avatar_path);
        $user->forceFill(['avatar_path' => null, 'avatar_mime' => null, 'avatar_updated_at' => null])->save();

        $self = $actor->id === $user->id;
        $this->audit->log($self ? 'user.avatar.removed' : 'admin.user.avatar_removed', $self ? 'user' : 'admin', $actor->id, 'user', $user->id, [], $request);
    }

    /**
     * Sign the user out of every application (tokens) and every browser (sessions).
     *
     * @return array{access_tokens: int, refresh_tokens: int, sessions: int}
     */
    public function signOutEverywhere(User $user, User $actor, ?Request $request = null): array
    {
        $counts = $this->endEverySession($user, keepSessionId: $actor->id === $user->id ? $request?->session()?->getId() : null);

        $self = $actor->id === $user->id;
        $this->audit->log($self ? 'user.tokens.revoked' : 'admin.user.signed_out', $self ? 'user' : 'admin', $actor->id, 'user', $user->id, $counts, $request);

        return $counts;
    }

    /**
     * Delete the account. Tokens, codes and reset links go with it (cascade);
     * other applications keep whatever they hold under the old subject id.
     */
    public function delete(User $user, User $actor, ?Request $request = null): void
    {
        if ($user->id === $actor->id) {
            throw new AccountRuleException('user', '자기 자신의 계정은 삭제할 수 없습니다.');
        }
        if ($user->isSuperAdmin() && $user->isActive()) {
            $this->guardAdminLoss($user, $actor, 'user');
        }

        $snapshot = $user->only(['username', 'name', 'role', 'status']);

        DB::transaction(function () use ($user) {
            DB::table('sessions')->where('user_id', $user->id)->delete();
            if ($user->avatar_path !== null) {
                Storage::disk('local')->delete($user->avatar_path);
            }
            $user->delete();
        });

        $this->audit->log('admin.user.deleted', 'admin', $actor->id, 'user', $user->id, $snapshot, $request);
    }

    private function guardAdminLoss(User $user, User $actor, string $field): void
    {
        if ($user->id === $actor->id) {
            throw new AccountRuleException($field, '자기 자신의 관리자 권한을 내리거나 계정을 비활성화할 수 없습니다. 다른 관리자에게 요청하세요.');
        }

        $others = User::query()
            ->where('role', User::ROLE_SUPER_ADMIN)
            ->where('status', User::STATUS_ACTIVE)
            ->whereKeyNot($user->id)
            ->exists();

        if (! $others) {
            throw new AccountRuleException($field, '마지막 관리자입니다. 다른 사람을 먼저 관리자로 지정하세요.');
        }
    }

    /**
     * @return array{access_tokens: int, refresh_tokens: int, sessions: int}
     */
    private function endEverySession(User $user, ?string $keepSessionId = null): array
    {
        $revoked = $this->resets->revokeCredentials($user);

        $sessions = DB::table('sessions')
            ->where('user_id', $user->id)
            ->when($keepSessionId !== null, fn ($q) => $q->where('id', '!=', $keepSessionId))
            ->delete();

        return $revoked + ['sessions' => $sessions];
    }

    private function passwordOrGenerated(?string $typed): string
    {
        // Twelve characters without look-alikes: read aloud or typed from a chat
        // message, a generated password is copied by a person, not a machine.
        if ($typed !== null && $typed !== '') {
            return $typed;
        }

        $alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $plain = '';
        for ($i = 0; $i < 12; $i++) {
            $plain .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }

        return $plain;
    }
}
