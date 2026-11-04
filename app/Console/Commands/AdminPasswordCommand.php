<?php

namespace App\Console\Commands;

use App\Models\Admin;
use App\Services\AuditLogger;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * Password recovery for the console.
 *
 * Needed because there is no self-service reset flow (no mail, no public
 * endpoints): if the last administrator forgets the password, this is the way
 * back in. Anyone who can run this already has container access, so it adds no
 * privilege that was not already implied.
 */
class AdminPasswordCommand extends Command
{
    protected $signature = 'sso:admin-password
                            {email? : administrator e-mail; omit to list the administrators}
                            {--password= : set this password instead of generating one}
                            {--disable : disable the account instead of changing the password}';

    protected $description = 'Set or generate the password of a console administrator';

    public function handle(AuditLogger $audit): int
    {
        $email = $this->argument('email');

        if ($email === null) {
            $admins = Admin::query()->orderBy('id')->get();
            if ($admins->isEmpty()) {
                $this->components->warn('No administrators exist. Run `php artisan sso:bootstrap`.');

                return self::SUCCESS;
            }

            $this->table(
                ['id', 'email', 'name', 'active', 'last login'],
                $admins->map(fn (Admin $a) => [
                    $a->id, $a->email, $a->name, $a->active ? 'yes' : 'no',
                    $a->last_login_at?->toDateTimeString() ?? 'never',
                ])->all(),
            );

            return self::SUCCESS;
        }

        $admin = Admin::query()->where('email', strtolower(trim((string) $email)))->first();
        if ($admin === null) {
            $this->components->error("No administrator with e-mail {$email}.");

            return self::FAILURE;
        }

        if ($this->option('disable')) {
            $admin->forceFill(['active' => false])->save();
            $audit->log('admin.cli.disabled', 'system', 'cli', 'admin', $admin->id, ['email' => $admin->email]);
            $this->components->info("Disabled {$admin->email}.");

            return self::SUCCESS;
        }

        $plain = (string) ($this->option('password') ?: Str::password(20));
        if (strlen($plain) < 12) {
            $this->components->error('The password must be at least 12 characters.');

            return self::FAILURE;
        }

        $admin->forceFill(['password' => Hash::make($plain), 'active' => true])->save();

        $audit->log('admin.cli.password_reset', 'system', 'cli', 'admin', $admin->id, ['email' => $admin->email]);

        $this->components->twoColumnDetail('administrator', $admin->email);
        $this->components->twoColumnDetail('password', $plain);
        $this->newLine();
        $this->line('This password is shown once and is not stored in plain text.');

        return self::SUCCESS;
    }
}
