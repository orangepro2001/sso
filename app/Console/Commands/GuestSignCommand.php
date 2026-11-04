<?php

namespace App\Console\Commands;

use App\Services\GuestService;
use Illuminate\Console\Command;

/**
 * Prints the signature a guest must present, so operators never hand-compute it.
 */
class GuestSignCommand extends Command
{
    protected $signature = 'sso:guest-sign {device_id : the stable environment value (hostname, machine-id, serial)}
                                              {--payload : also print the signed payload}';

    protected $description = 'Compute the HMAC signature for a guest device id';

    public function handle(GuestService $guests): int
    {
        $deviceId = (string) $this->argument('device_id');

        if ((string) config('sso.guest.secret', '') === '') {
            $this->components->error('SSO_GUEST_SECRET is empty; signatures cannot be computed.');

            return self::FAILURE;
        }

        if ($this->option('payload')) {
            $this->components->twoColumnDetail('payload', $guests->signedPayload($deviceId));
        }

        $this->components->twoColumnDetail('device_id', $deviceId);
        $this->components->twoColumnDetail('algo', $guests->algorithm());
        $this->components->twoColumnDetail('signature', $guests->sign($deviceId));

        $this->newLine();
        $this->line('curl -sS -X POST '.rtrim((string) config('sso.issuer'), '/').'/oauth/guest \');
        $this->line('  -H "Content-Type: application/json" \');
        $this->line('  -d '.escapeshellarg(json_encode([
            'device_id' => $deviceId,
            'algo' => $guests->algorithm(),
            'signature' => $guests->sign($deviceId),
        ], JSON_UNESCAPED_SLASHES)));

        return self::SUCCESS;
    }
}
