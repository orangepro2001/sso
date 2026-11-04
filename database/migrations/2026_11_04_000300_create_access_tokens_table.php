<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // One row per issued access token. JWTs are stored by jti (so revocation
        // and blacklisting are instant); guest tokens are opaque and stored by hash.
        Schema::create('access_tokens', function (Blueprint $table) {
            $table->id();
            $table->string('kind', 16)->default('jwt');      // jwt | opaque
            $table->string('jti', 64)->unique();
            $table->string('token_hash', 64)->nullable()->unique();
            $table->string('subject_type', 16);              // user | guest | client
            $table->foreignId('user_id')->nullable()->constrained()->cascadeOnDelete();
            $table->foreignId('guest_device_id')->nullable()->constrained('guest_devices')->cascadeOnDelete();
            $table->string('client_id', 64)->nullable()->index();
            $table->json('scopes');
            $table->timestamp('expires_at')->nullable();     // null = never expires (guests)
            $table->timestamp('revoked_at')->nullable();
            $table->string('issued_ip', 45)->nullable();
            $table->string('user_agent', 512)->nullable();
            $table->timestamps();

            $table->index(['subject_type', 'expires_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('access_tokens');
    }
};
