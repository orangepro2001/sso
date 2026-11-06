<?php

namespace App\Support;

use App\Models\AuditLog;
use App\Models\OauthClient;
use App\Models\User;
use Illuminate\Support\Collection;

/**
 * Turns audit rows into sentences a person can read: "정태훈 님이 로그인" instead of
 * `login.succeeded user:6 user:6`. The raw event and metadata stay one click away
 * in the activity page, for when the sentence is not enough.
 */
final class AuditPresenter
{
    private const LABELS = [
        'login.succeeded' => '로그인',
        'login.failed' => '로그인 실패',
        'login.denied' => '로그인 거부 (비활성 계정)',
        'logout' => '로그아웃',
        'user.logout' => '로그아웃',
        'admin.login.succeeded' => '콘솔 로그인',
        'admin.login.failed' => '콘솔 로그인 실패',
        'user.register' => '회원가입',
        'authorize.granted' => '앱에 로그인',
        'authorize.denied' => '앱 로그인 거부',
        'token.issued' => '앱 토큰 발급',
        'token.revoked' => '앱 토큰 폐기',
        'token.error' => '토큰 요청 오류',
        'token.introspected' => '토큰 조회',
        'token.reuse_detected' => '갱신 토큰 재사용 감지',
        'token.family_revoked' => '갱신 토큰 묶음 폐기',
        'admin.user.created' => '계정 생성',
        'admin.user.updated' => '계정 정보 변경',
        'admin.user.password_reset' => '관리자가 비밀번호 설정',
        'admin.user.reset_link_created' => '비밀번호 재설정 링크 발급',
        'admin.user.avatar_updated' => '관리자가 사진 변경',
        'admin.user.avatar_removed' => '관리자가 사진 삭제',
        'admin.user.signed_out' => '관리자가 모든 곳에서 로그아웃',
        'admin.user.deleted' => '계정 삭제',
        'admin.cli.user_disabled' => '명령줄에서 계정 비활성화',
        'admin.cli.user_password_reset' => '명령줄에서 비밀번호 설정',
        'admin.cli.user_role' => '명령줄에서 권한 변경',
        'admin.bootstrap.created' => '최초 관리자 생성',
        'admin.password_changed' => '비밀번호 변경',
        'user.profile.updated' => '프로필 변경',
        'user.avatar.updated' => '사진 변경',
        'user.avatar.removed' => '사진 삭제',
        'user.password.changed' => '비밀번호 변경',
        'user.password.change_rejected' => '비밀번호 변경 실패',
        'user.password_reset.completed' => '링크로 비밀번호 재설정',
        'user.password_reset.rejected' => '재설정 링크 거부',
        'user.tokens.revoked' => '모든 곳에서 로그아웃',
        'admin.client.created' => '앱 등록',
        'admin.client.updated' => '앱 설정 변경',
        'maintenance.pruned' => '만료 데이터 정리',
    ];

    /** Filter chips on the activity page: label => event prefixes. */
    public const CATEGORIES = [
        'login' => ['로그인', ['login.', 'logout', 'user.logout', 'admin.login.', 'authorize.', 'user.register']],
        'account' => ['계정 변경', ['admin.user.', 'admin.cli.', 'user.profile.', 'user.avatar.', 'user.password', 'user.tokens.']],
        'token' => ['토큰', ['token.']],
        'app' => ['앱 설정', ['admin.client.']],
    ];

    private const FIELDS = ['name' => '이름', 'username' => '아이디', 'note' => '메모', 'role' => '권한', 'status' => '상태'];

    private const VALUES = [
        User::ROLE_SUPER_ADMIN => '관리자', User::ROLE_USER => '일반',
        User::STATUS_ACTIVE => '활성', User::STATUS_DISABLED => '비활성',
    ];

    public static function label(string $event): string
    {
        return self::LABELS[$event] ?? $event;
    }

    /** '' | 'bad' | 'warn' — the badge colour of an event. */
    public static function tone(string $event): string
    {
        return match (true) {
            str_contains($event, 'failed'), str_contains($event, 'denied'), str_contains($event, 'rejected'),
            str_contains($event, 'error'), str_contains($event, 'reuse'), $event === 'admin.user.deleted' => 'bad',
            str_contains($event, 'password'), str_contains($event, 'signed_out'), str_contains($event, 'tokens.revoked'),
            str_contains($event, 'disabled') => 'warn',
            default => '',
        };
    }

    /**
     * Names for every user id mentioned as actor or subject of these rows.
     *
     * @param  Collection<int, AuditLog>  $logs
     * @return Collection<int|string, string>
     */
    public static function people(Collection $logs): Collection
    {
        $ids = $logs->flatMap(fn (AuditLog $log) => [
            in_array($log->actor_type, ['user', 'admin'], true) ? $log->actor_id : null,
            $log->subject_type === 'user' ? $log->subject_id : null,
        ])->filter(fn ($id) => $id !== null && ctype_digit((string) $id))->unique();

        return $ids->isEmpty() ? collect() : User::query()->whereIn('id', $ids)->pluck('name', 'id');
    }

    /** @return Collection<string, string> client_id => name */
    public static function clients(): Collection
    {
        return OauthClient::query()->pluck('name', 'client_id');
    }

    /**
     * Who did it, in words.
     *
     * @param  Collection<int|string, string>  $people
     */
    public static function actor(AuditLog $log, Collection $people): string
    {
        return match ($log->actor_type) {
            'user', 'admin' => $people[$log->actor_id] ?? '삭제된 사용자 #'.$log->actor_id,
            'anonymous' => '(로그인 전) '.$log->actor_id,
            'system' => '시스템',
            null => '—',
            default => $log->actor_type.($log->actor_id ? ':'.$log->actor_id : ''),
        };
    }

    /**
     * Whom it was done to, when that is not the actor.
     *
     * @param  Collection<int|string, string>  $people
     */
    public static function subject(AuditLog $log, Collection $people, ?Collection $clients = null): ?string
    {
        if ($log->subject_type === 'user') {
            if ($log->subject_id === $log->actor_id && in_array($log->actor_type, ['user', 'admin'], true)) {
                return null;
            }

            return $people[$log->subject_id] ?? ($log->meta['username'] ?? '#'.$log->subject_id);
        }

        if ($log->subject_type === 'client') {
            return ($clients ?? self::clients())[$log->subject_id] ?? $log->subject_id;
        }

        return null;
    }

    /** One line of detail from the metadata, or '' when there is nothing useful. */
    public static function detail(AuditLog $log, ?Collection $clients = null): string
    {
        $meta = $log->meta ?? [];

        if ($log->event === 'admin.user.updated' && isset($meta['changed'])) {
            return collect($meta['changed'])->map(function ($field) use ($meta) {
                $from = $meta['from'][$field] ?? '';
                $to = $meta['to'][$field] ?? '';
                $label = self::FIELDS[$field] ?? $field;

                return $field === 'note'
                    ? $label
                    : $label.' '.(self::VALUES[$from] ?? $from).' → '.(self::VALUES[$to] ?? $to);
            })->implode(', ');
        }

        if ($log->event === 'user.profile.updated' && isset($meta['from'], $meta['to'])) {
            return collect(['name', 'username'])
                ->filter(fn ($k) => ($meta['from'][$k] ?? null) !== ($meta['to'][$k] ?? null))
                ->map(fn ($k) => self::FIELDS[$k].' '.$meta['from'][$k].' → '.$meta['to'][$k])
                ->implode(', ');
        }

        if (isset($meta['client_id'])) {
            return (string) (($clients ?? self::clients())[$meta['client_id']] ?? $meta['client_id']);
        }

        if (isset($meta['role']) && $log->event === 'admin.user.created') {
            return '권한 '.(self::VALUES[$meta['role']] ?? $meta['role']);
        }

        if (isset($meta['reason'])) {
            return (string) $meta['reason'];
        }

        return '';
    }
}
