<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Profile pictures, stored on this host (no image host, no external avatar service).
 *
 * `avatar_updated_at` is the cache key: the URL carries it, so replacing a picture
 * changes the URL and no cache anywhere has to be invalidated.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('avatar_path')->nullable()->after('name');
            $table->string('avatar_mime', 64)->nullable()->after('avatar_path');
            $table->timestamp('avatar_updated_at')->nullable()->after('avatar_mime');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['avatar_path', 'avatar_mime', 'avatar_updated_at']);
        });
    }
};
