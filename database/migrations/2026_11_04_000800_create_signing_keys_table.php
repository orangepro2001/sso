<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // RS256 key pair, generated on first boot and kept in the database so the
        // container filesystem can stay read-only. The private key is encrypted
        // with APP_KEY by the model cast.
        Schema::create('signing_keys', function (Blueprint $table) {
            $table->id();
            $table->string('kid', 64)->unique();
            $table->string('alg', 8)->default('RS256');
            $table->text('private_key');
            $table->text('public_key');
            $table->boolean('active')->default(true);
            $table->timestamp('retired_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('signing_keys');
    }
};
