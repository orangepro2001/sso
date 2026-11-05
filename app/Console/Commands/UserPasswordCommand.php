<?php

namespace App\Console\Commands;

use App\Models\User;
use App\Services\AuditLogger;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * Set or generate a user's password from the shell.
 *
 * Needed because a password is stored hashed and shown once: if it was lost before
 * it reached the user, there is nothing to recover and no mail flow to fall back
 * on. Anyone who can run this already has container access.
 */
class UserPasswordCommand extends Command
{
    protected $signature = 'sso:user-password
                            {username? : user to reset; omit to list users}
                            {--password= : set this password instead of generating one}
                            {--disable : disable the account instead of changing the password}';

    protected $description = 'Set or generate the password of an SSO user';

    public function handle(AuditLogger $audit): int
    {
        $username = $this->argument('username');

        if ($username === null) {
            $users = User::query()->orderBy('id')->get();
            if ($users->isEmpty()) {
                $this->components->warn('No users exist yet.');

                return self::SUCCESS;
            }

            $this->table(
                ['id', 'username', 'name', 'status', 'last login'],
                $users->map(fn (User $u) => [
                    $u->id, $u->username, $u->name, $u->status,
                    $u->last_login_at?->toDateTimeString() ?? 'never',
                ])->all(),
            );

            return self::SUCCESS;
        }

        $user = User::query()->where('username', strtolower(trim((string) $username)))->first();
        if ($user === null) {
            $this->components->error("No user with username {$username}.");

            return self::FAILURE;
        }

        if ($this->option('disable')) {
            $user->forceFill(['status' => User::STATUS_DISABLED])->save();
            $audit->log('admin.cli.user_disabled', 'system', 'cli', 'user', $user->id, ['username' => $user->username]);
            $this->components->info("Disabled {$user->username}.");

            return self::SUCCESS;
        }

        $plain = (string) ($this->option('password') ?: Str::password(20, symbols: false));
        if (strlen($plain) < 12) {
            $this->components->error('The password must be at least 12 characters.');

            return self::FAILURE;
        }

        $user->forceFill(['password' => Hash::make($plain)])->save();

        $audit->log('admin.cli.user_password_reset', 'system', 'cli', 'user', $user->id, ['username' => $user->username]);

        $this->components->twoColumnDetail('user', $user->username);
        $this->components->twoColumnDetail('password', $plain);
        $this->newLine();
        $this->line('Shown once; it is stored hashed and cannot be read back.');

        return self::SUCCESS;
    }
}
