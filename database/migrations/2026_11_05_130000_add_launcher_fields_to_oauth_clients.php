<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Which applications the launcher offers, and where each one starts.
 *
 * An OAuth client already knows what it is called and which redirect URIs are legal;
 * what it did not know is the page a person opens to *use* it. That URL plus an order
 * is the whole launcher — curated by an administrator in the console, not a config file
 * nobody can edit at runtime.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table) {
            // Blank = registered for machine-to-machine use only: it never appears in
            // the launcher, because a person has nowhere to go.
            $table->string('home_url', 500)->nullable()->after('redirect_uris');
            $table->unsignedSmallInteger('sort_order')->default(0)->after('home_url');
            $table->boolean('in_launcher')->default(true)->after('sort_order');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table) {
            $table->dropColumn(['home_url', 'sort_order', 'in_launcher']);
        });
    }
};
