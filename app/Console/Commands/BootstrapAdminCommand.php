<?php

namespace App\Console\Commands;

use App\Models\Admin;
use App\Services\AuditLogger;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * Bootstrap (and emergency) administrator creation.
 *
 * Normal account provisioning happens in the console, but the very first
 * administrator has to come from somewhere: this reads the environment and is a
 * no-op once at least one admin exists, so it is safe to run on every boot.
 */
class BootstrapAdminCommand extends Command
{
    protected $signature = 'sso:bootstrap {--force : reset the bootstrap admin password even if admins exist}';

    protected $description = 'Create the bootstrap administrator from the environment (no-op when admins exist)';

    public function handle(AuditLogger $audit): int
    {
        $email = strtolower(trim((string) config('sso.bootstrap.email', '')));
        $password = $this->password();

        if ($email === '') {
            $this->components->warn('SSO_BOOTSTRAP_ADMIN_EMAIL is empty; skipping.');

            return self::SUCCESS;
        }

        $existing = Admin::query()->count();
        if ($existing > 0 && ! $this->option('force')) {
            $this->components->info("{$existing} administrator(s) already exist; nothing to do.");

            return self::SUCCESS;
        }

        if ($password === '') {
            $this->components->error('No bootstrap password: set SSO_BOOTSTRAP_ADMIN_PASSWORD or SSO_BOOTSTRAP_ADMIN_PASSWORD_FILE.');

            return self::FAILURE;
        }

        if (strlen($password) < 12) {
            $this->components->error('The bootstrap password must be at least 12 characters.');

            return self::FAILURE;
        }

        $admin = Admin::query()->firstOrNew(['email' => $email]);
        $created = ! $admin->exists;

        $admin->fill([
            'name' => (string) config('sso.bootstrap.name', 'admin'),
            'password' => Hash::make($password),
            'active' => true,
        ])->save();

        $audit->log($created ? 'admin.bootstrap.created' : 'admin.bootstrap.password_reset', 'system', 'bootstrap', 'admin', $admin->id, [
            'email' => $email,
        ]);

        $this->components->info(($created ? 'Created' : 'Updated')." bootstrap administrator {$email}.");

        return self::SUCCESS;
    }

    private function password(): string
    {
        $inline = (string) config('sso.bootstrap.password', '');
        if ($inline !== '') {
            return $inline;
        }

        $file = (string) config('sso.bootstrap.password_file', '');
        if ($file !== '' && is_readable($file)) {
            return trim((string) file_get_contents($file));
        }

        return '';
    }
}
