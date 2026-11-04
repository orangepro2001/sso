<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The console login form offers "remember this browser", and Laravel's session
 * guard writes remember_token when it is used. The column was missing, so ticking
 * the box made the login itself fail with an undefined-column error.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('admins', function (Blueprint $table) {
            $table->rememberToken();
        });
    }

    public function down(): void
    {
        Schema::table('admins', function (Blueprint $table) {
            $table->dropRememberToken();
        });
    }
};
