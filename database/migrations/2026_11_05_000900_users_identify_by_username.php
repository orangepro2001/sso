<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Users identify themselves with a username, not an e-mail address.
 *
 * Requirements were: display name (nickname), username, password. Nothing else.
 * The e-mail column is therefore dropped, and existing rows are migrated by taking
 * the local part of their address (yzy@egg.email.com -> yzy), de-duplicated so the
 * unique index can be created afterwards.
 *
 * Administrators keep their e-mail: they are a different identity space and are
 * not user accounts.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('users', 'username')) {
            Schema::table('users', function (Blueprint $table) {
                $table->string('username', 64)->nullable()->after('name');
            });
        }

        if (Schema::hasColumn('users', 'email')) {
            $this->backfillUsernames();
        }

        // Validate before tightening: a silent default would be worse than a loud
        // failure during a deploy, and this table is small.
        $unusable = DB::table('users')->whereNull('username')->orWhere('username', '')->count();
        if ($unusable > 0) {
            throw new RuntimeException("{$unusable} user row(s) could not be given a username; fix them and re-run.");
        }

        Schema::table('users', function (Blueprint $table) {
            $table->string('username', 64)->nullable(false)->change();
            $table->unique('username');
        });

        if (Schema::hasColumn('users', 'email')) {
            Schema::table('users', function (Blueprint $table) {
                $table->dropUnique(['email']);
                $table->dropColumn('email');
            });
        }
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('email')->nullable()->after('name');
        });

        // Reverse the backfill: username@users.invalid is a placeholder, not a
        // claim that mail is delivered anywhere.
        DB::table('users')->update(['email' => DB::raw("username || '@users.invalid'")]);

        Schema::table('users', function (Blueprint $table) {
            $table->string('email')->nullable(false)->change();
            $table->unique('email');
            $table->dropUnique(['username']);
            $table->dropColumn('username');
        });
    }

    private function backfillUsernames(): void
    {
        $taken = [];

        foreach (DB::table('users')->orderBy('id')->get(['id', 'email', 'name']) as $row) {
            $base = $this->slug($row->email !== null ? strstr($row->email, '@', true) : null);
            if ($base === '') {
                $base = $this->slug($row->name) ?: 'user'.$row->id;
            }

            $candidate = $base;
            $suffix = 1;
            while (isset($taken[$candidate])) {
                $candidate = $base.'-'.(++$suffix);
            }
            $taken[$candidate] = true;

            DB::table('users')->where('id', $row->id)->update(['username' => $candidate]);
        }
    }

    private function slug(?string $value): string
    {
        $value = strtolower(trim((string) $value));
        // Usernames are typed at a login prompt: keep them boring ASCII.
        $value = (string) preg_replace('/[^a-z0-9._-]+/', '-', $value);

        return trim($value, '-._');
    }
};
