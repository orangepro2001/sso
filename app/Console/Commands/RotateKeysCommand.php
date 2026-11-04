<?php

namespace App\Console\Commands;

use App\Services\SigningKeyService;
use Illuminate\Console\Command;

class RotateKeysCommand extends Command
{
    protected $signature = 'sso:keys:rotate';

    protected $description = 'Retire the active RS256 key and generate a new one';

    public function handle(SigningKeyService $keys): int
    {
        $key = $keys->rotate();

        $this->components->info("New active signing key: {$key->kid}");

        return self::SUCCESS;
    }
}
