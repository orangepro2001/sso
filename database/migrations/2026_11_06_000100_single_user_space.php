<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * One account space: the console is a user with role `super_admin`, not a separate
 * e-mail account. Every "who did this" column that pointed at `admins` now points at
 * `users`. Admin ids do not map to user ids, so those columns are cleared; the audit
 * log still records who did what.
 */
return new class extends Migration
{
    /** @var array<int, array{0: string, 1: string}> */
    private array $actorColumns = [
        ['users', 'created_by'],
        ['oauth_clients', 'created_by'],
        ['blacklist_entries', 'created_by'],
        ['user_password_resets', 'created_by'],
        ['registration_invites', 'created_by'],
        ['guest_devices', 'reviewed_by'],
    ];

    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('role', 32)->default('user')->after('username');
        });

        $this->repoint('users');
    }

    public function down(): void
    {
        $this->repoint('admins');

        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('role');
        });
    }

    private function repoint(string $target): void
    {
        foreach ($this->actorColumns as [$table, $column]) {
            Schema::table($table, fn (Blueprint $t) => $t->dropForeign([$column]));
            DB::table($table)->update([$column => null]);
            Schema::table($table, fn (Blueprint $t) => $t->foreign($column)->references('id')->on($target)->nullOnDelete());
        }
    }
};
