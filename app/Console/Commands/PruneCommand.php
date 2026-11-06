<?php

namespace App\Console\Commands;

use App\Models\AccessToken;
use App\Models\AuditLog;
use App\Models\OauthAuthCode;
use App\Models\RefreshToken;
use App\Services\AuditLogger;
use Illuminate\Console\Command;

/**
 * Housekeeping: rows that can no longer authenticate anything (expired or revoked
 * tokens, spent authorization codes) and audit entries past their retention.
 */
class PruneCommand extends Command
{
    protected $signature = 'sso:prune
                            {--audit-days=90 : delete audit entries older than this}
                            {--dry-run : report what would be deleted}';

    protected $description = 'Delete expired tokens, spent authorization codes and old audit entries';

    public function handle(AuditLogger $audit): int
    {
        $dry = (bool) $this->option('dry-run');
        $auditDays = max(1, (int) $this->option('audit-days'));

        $counts = [];

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

    private function delete($query, bool $dry): int
    {
        return $dry ? $query->count() : $query->delete();
    }
}
