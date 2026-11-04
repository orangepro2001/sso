<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Daily log: one row per member per calendar day.
 *
 * The workbook is a *daily* report (업무일보): the header carries the report date,
 * the author and the department, and the body lists the tasks that person is
 * working on. A `daily_logs` row freezes those header values (plus a submitted
 * marker) so a past day cannot silently change when someone edits a card.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('daily_logs', function (Blueprint $table) {
            $table->id();
            $table->date('log_date');
            $table->foreignId('member_id')->constrained()->cascadeOnDelete();
            // Snapshot of the header block (부서 / 작성자) at submit time.
            $table->string('department', 120)->nullable();
            $table->string('author_name', 80)->nullable();
            // draft | submitted — submitted makes the export reproducible.
            $table->string('state', 10)->default('draft');
            $table->timestamp('submitted_at')->nullable();
            // Free-form shift note; the workbook has no field for it, kept for the UI.
            $table->string('mood', 200)->nullable();
            $table->timestamps();

            $table->unique(['log_date', 'member_id']);
            $table->index(['log_date', 'state']);
        });

        // Which issues a member touched on a given day, and how much progress moved.
        Schema::create('work_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('daily_log_id')->constrained()->cascadeOnDelete();
            $table->foreignId('issue_id')->constrained()->cascadeOnDelete();
            $table->foreignId('member_id')->constrained()->cascadeOnDelete();
            $table->date('logged_on');
            $table->unsignedSmallInteger('percent_from')->nullable();
            $table->unsignedSmallInteger('percent_to')->nullable();
            // Minutes spent; optional, powers the "공수" summary.
            $table->unsignedSmallInteger('minutes')->nullable();
            $table->string('note', 500)->nullable();
            $table->timestamps();

            $table->index(['logged_on', 'member_id']);
            $table->index(['issue_id', 'logged_on']);
            $table->unique(['logged_on', 'issue_id', 'member_id']);
        });

        Schema::create('attachments', function (Blueprint $table) {
            $table->id();
            $table->morphs('attachable');
            $table->foreignId('uploader_id')->nullable()->constrained('members')->nullOnDelete();
            $table->string('disk', 40)->default('local');
            $table->string('path', 500);
            $table->string('original_name', 255);
            $table->string('mime_type', 120)->nullable();
            $table->unsignedBigInteger('size')->default(0);
            $table->timestamps();

            $table->index(['uploader_id', 'created_at']);
        });

        Schema::create('notifications', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('type');
            $table->morphs('notifiable');
            $table->text('data');
            $table->timestamp('read_at')->nullable();
            $table->timestamps();

            $table->index(['notifiable_type', 'notifiable_id', 'read_at']);
        });

        // Saved JQL-lite filters per member ("내 이슈", "이번 주 마감").
        Schema::create('saved_filters', function (Blueprint $table) {
            $table->id();
            $table->foreignId('member_id')->constrained()->cascadeOnDelete();
            $table->string('name', 80);
            $table->jsonb('query');
            $table->boolean('shared')->default(false);
            $table->timestamps();

            $table->index(['member_id', 'name']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('saved_filters');
        Schema::dropIfExists('notifications');
        Schema::dropIfExists('attachments');
        Schema::dropIfExists('work_logs');
        Schema::dropIfExists('daily_logs');
    }
};
