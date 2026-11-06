<?php

namespace App\Console\Commands;

use App\Models\User;
use App\Services\AuditLogger;
use Illuminate\Console\Command;

/**
 * Bootstrap (and emergency) super administrator.
 *
 * The console is open to users with role super_admin, and the first one has to come
 * from somewhere: this reads the environment and is a no-op once any active super
 * administrator exists, so it is safe to run on every boot.
 */
class BootstrapAdminCommand extends Command
{
    protected $signature = 'sso:bootstrap {--force : reset the bootstrap user\'s password and role even if a super administrator exists}';

    protected $description = 'Create the bootstrap super administrator from the environment (no-op when one exists)';

    public function handle(AuditLogger $audit): int
    {
        $username = strtolower(trim((string) config('sso.bootstrap.username', '')));
        if ($username === '') {
            $this->components->warn('SSO_BOOTSTRAP_ADMIN_USERNAME is empty; skipping.');

            return self::SUCCESS;
        }

        $existing = User::query()->where('role', User::ROLE_SUPER_ADMIN)->where('status', User::STATUS_ACTIVE)->count();
        if ($existing > 0 && ! $this->option('force')) {
            $this->components->info("{$existing} super administrator(s) already exist; nothing to do.");

            return self::SUCCESS;
        }

        $password = $this->password();
        if ($password === '') {
            $this->components->error('No bootstrap password: set SSO_BOOTSTRAP_ADMIN_PASSWORD or SSO_BOOTSTRAP_ADMIN_PASSWORD_FILE.');

            return self::FAILURE;
        }

        $user = User::query()->firstOrNew(['username' => $username]);
        $created = ! $user->exists;

        $user->fill([
            'name' => $user->name ?: (string) config('sso.bootstrap.name', 'admin'),
            'password' => $password,
            'role' => User::ROLE_SUPER_ADMIN,
            'status' => User::STATUS_ACTIVE,
        ])->save();

        $audit->log($created ? 'admin.bootstrap.created' : 'admin.bootstrap.password_reset', 'system', 'bootstrap', 'user', $user->id, [
            'username' => $username,
        ]);

        $this->components->info(($created ? 'Created' : 'Updated')." bootstrap super administrator {$username}.");

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
