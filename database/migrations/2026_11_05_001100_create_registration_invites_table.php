<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Administrator-issued registration invites.
 *
 * Registration stays closed — the design has no public sign-up — but handing out a
 * one-time code beats hand-creating every account and telling somebody their
 * password. Only the SHA-256 of the code is stored; the plaintext is shown once, to
 * the administrator who minted it.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('registration_invites', function (Blueprint $table) {
            $table->id();
            $table->string('code_hash', 64)->unique();
            $table->string('note')->nullable();
            $table->foreignId('created_by')->nullable()->constrained('admins')->nullOnDelete();
            $table->timestamp('expires_at');
            $table->timestamp('used_at')->nullable();
            $table->string('used_ip', 45)->nullable();
            $table->foreignId('used_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->index(['used_at', 'expires_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('registration_invites');
    }
};
