<?php

namespace App\Console\Commands;

use App\Models\User;
use App\Services\AuditLogger;
use Illuminate\Console\Command;

/**
 * Show or change a user's role from the shell — the way back in if the last super
 * administrator demotes themselves.
 */
class UserRoleCommand extends Command
{
    protected $signature = 'sso:role
                            {username : the user}
                            {role? : user | super_admin; omit to print the current role}';

    protected $description = 'Show or set the role of an SSO user';

    public function handle(AuditLogger $audit): int
    {
        $user = User::query()->where('username', strtolower(trim((string) $this->argument('username'))))->first();
        if ($user === null) {
            $this->components->error('No user with username '.$this->argument('username').'.');

            return self::FAILURE;
        }

        $role = $this->argument('role');
        if ($role === null) {
            $this->line($user->role);

            return self::SUCCESS;
        }

        if (! in_array($role, User::ROLES, true)) {
            $this->components->error('Role must be one of: '.implode(', ', User::ROLES).'.');

            return self::FAILURE;
        }

        $from = $user->role;
        $user->forceFill(['role' => $role])->save();
        $audit->log('admin.cli.user_role', 'system', 'cli', 'user', $user->id, [
            'username' => $user->username, 'from' => $from, 'to' => $role,
        ]);
        $this->components->info("{$user->username}: {$from} → {$role}.");

        return self::SUCCESS;
    }
}
