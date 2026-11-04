<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Silently enrolled guests. Review is a posteriori: the first request from
        // a validly signed device is approved at once and reviewed by a human later.
        Schema::create('guest_devices', function (Blueprint $table) {
            $table->id();
            $table->string('device_id', 191)->unique();
            $table->string('status', 16)->default('active'); // active | blacklisted
            $table->unsignedInteger('request_count')->default(0);
            $table->string('first_seen_ip', 45)->nullable();
            $table->string('last_seen_ip', 45)->nullable();
            $table->string('first_user_agent', 512)->nullable();
            $table->string('last_user_agent', 512)->nullable();
            $table->timestamp('first_seen_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->timestamp('reviewed_at')->nullable();
            $table->foreignId('reviewed_by')->nullable()->constrained('admins')->nullOnDelete();
            $table->text('note')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('guest_devices');
    }
};
