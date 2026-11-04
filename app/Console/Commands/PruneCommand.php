<?php

namespace App\Console\Commands;

use App\Models\AccessToken;
use App\Models\AuditLog;
use App\Models\GuestDevice;
use App\Models\OauthAuthCode;
use App\Models\RefreshToken;
use App\Services\AuditLogger;
use Illuminate\Console\Command;

/**
 * Housekeeping. Guest tokens never expire, so a device that calls /oauth/guest
 * forever would accumulate one access_tokens row per call; nothing else in the
 * design would ever remove them.
 *
 * Safe by construction: only dead rows are touched. A guest device keeps its
 * current (newest) live token, and everything else that is expired, revoked or
 * consumed goes.
 */
class PruneCommand extends Command
{
    protected $signature = 'sso:prune
                            {--audit-days=90 : delete audit entries older than this}
                            {--device-days=180 : forget guest devices unseen for this long}
                            {--dry-run : report what would be deleted}';

    protected $description = 'Delete expired tokens, old authorization codes and stale guest devices';

    public function handle(AuditLogger $audit): int
    {
        $dry = (bool) $this->option('dry-run');
        $auditDays = max(1, (int) $this->option('audit-days'));
        $deviceDays = max(1, (int) $this->option('device-days'));

        $counts = [];

        // Expired or revoked access tokens. Guest tokens have no expiry, so the
        // "superseded" clause is what actually trims them.
        $counts['superseded guest tokens'] = $this->delete(
            AccessToken::query()
                ->where('subject_type', AccessToken::SUBJECT_GUEST)
                ->whereNull('revoked_at')
                ->whereIn('id', $this->supersededGuestTokenIds()),
            $dry,
        );

        $counts['dead access tokens'] = $this->delete(
            AccessToken::query()->where(function ($q) {
                $q->whereNotNull('revoked_at')
                    ->orWhere(fn ($w) => $w->whereNotNull('expires_at')->where('expires_at', '<', now()));
            }),
            $dry,
        );

        $counts['dead refresh tokens'] = $this->delete(
            RefreshToken::query()->where(function ($q) {
                $q->whereNotNull('revoked_at')
                    ->orWhere(fn ($w) => $w->where('expires_at', '<', now()));
            }),
            $dry,
        );

        $counts['spent authorization codes'] = $this->delete(
            OauthAuthCode::query()->where(function ($q) {
                $q->whereNotNull('consumed_at')->orWhere('expires_at', '<', now());
            }),
            $dry,
        );

        $cutoff = now()->subDays($deviceDays);
        $counts['stale guest devices'] = $this->delete(
            GuestDevice::query()
                ->where('status', GuestDevice::STATUS_ACTIVE)
                ->where(fn ($q) => $q->whereNull('last_seen_at')->orWhere('last_seen_at', '<', $cutoff)),
            $dry,
        );

        $counts['old audit entries'] = $this->delete(
            AuditLog::query()->where('created_at', '<', now()->subDays($auditDays)),
            $dry,
        );

        $this->table(['what', $dry ? 'would delete' : 'deleted'], collect($counts)
            ->map(fn ($n, $k) => [$k, $n])->values()->all());

        if (! $dry) {
            $audit->log('maintenance.pruned', 'system', 'cli', null, null, $counts);
        }

        return self::SUCCESS;
    }

    /**
     * Ids of guest tokens that have been superseded by a newer live token for the
     * same device. The newest one is always kept.
     *
     * @return array<int, int>
     */
    private function supersededGuestTokenIds(): array
    {
        $ids = [];
        $keep = [];

        $rows = AccessToken::query()
            ->where('subject_type', AccessToken::SUBJECT_GUEST)
            ->whereNull('revoked_at')
            ->orderByDesc('id')
            ->get(['id', 'guest_device_id']);

        foreach ($rows as $row) {
            if (isset($keep[$row->guest_device_id])) {
                $ids[] = $row->id;
            } else {
                $keep[$row->guest_device_id] = true;
            }
        }

        return $ids;
    }

    private function delete($query, bool $dry): int
    {
        return $dry ? $query->count() : $query->delete();
    }
}
