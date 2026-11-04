<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Deny list checked on every introspection. kind=device matches guest_devices.device_id.
        Schema::create('blacklist_entries', function (Blueprint $table) {
            $table->id();
            $table->string('kind', 16);              // device | user | token | client
            $table->string('value', 191);            // device_id | user id | jti | client_id
            $table->string('reason', 512)->nullable();
            $table->foreignId('created_by')->nullable()->constrained('admins')->nullOnDelete();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();

            $table->unique(['kind', 'value']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blacklist_entries');
    }
};
