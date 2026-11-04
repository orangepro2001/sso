<?php

namespace App\Services;

use App\Models\AuditLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Append-only audit trail. Everything security relevant goes through here:
 * logins, account creation, guest enrolment, blacklisting and token lifecycle.
 */
class AuditLogger
{
    /**
     * @param  array<string, mixed>  $meta
     */
    public function log(
        string $event,
        ?string $actorType = null,
        int|string|null $actorId = null,
        ?string $subjectType = null,
        int|string|null $subjectId = null,
        array $meta = [],
        ?Request $request = null,
    ): void {
        $request ??= request();

        try {
            AuditLog::create([
                'event' => $event,
                'actor_type' => $actorType,
                'actor_id' => $actorId === null ? null : (string) $actorId,
                'subject_type' => $subjectType,
                'subject_id' => $subjectId === null ? null : (string) $subjectId,
                'ip' => $this->ip($request),
                'user_agent' => $this->agent($request),
                'meta' => $meta === [] ? null : $meta,
                'created_at' => now(),
            ]);
        } catch (Throwable $e) {
            // Never let an audit failure break the auth flow, but do shout about it.
            Log::error('audit log write failed', ['event' => $event, 'error' => $e->getMessage()]);
        }
    }

    public function ip(?Request $request = null): ?string
    {
        $value = ($request ?? request())->ip();

        return $value === null ? null : substr($value, 0, 45);
    }

    public function agent(?Request $request = null): ?string
    {
        $value = ($request ?? request())->userAgent();

        return $value === null ? null : substr($value, 0, 512);
    }
}
