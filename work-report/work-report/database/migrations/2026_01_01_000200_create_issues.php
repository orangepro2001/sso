<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Issues, the Jira-shaped core.
 *
 * An issue is simultaneously the board card and the Excel row: the columns
 * `summary`, `priority_key`, `status_key`, `percent`, `starts_on`, `due_on`,
 * `note` map one to one onto 업무 내용 / 우선순위 / 상태 / 진행률 / 시작일 /
 * 예정일 / 비고 in the reference workbook (docs/excel-schema.md).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('issues', function (Blueprint $table) {
            $table->id();
            $table->foreignId('project_id')->constrained()->cascadeOnDelete();
            $table->foreignId('sprint_id')->nullable()->constrained()->nullOnDelete();
            // Per-project monotonically increasing number; the printable key is
            // projects.abbr . '-' . issue_no (e.g. 3D-01). Allocated inside a
            // transaction with a row lock, see App\Services\IssueKeyGenerator.
            $table->unsignedInteger('issue_no');
            $table->string('summary', 300);
            $table->text('description')->nullable();

            // Priority: High / Medium / Low. Kept as a short key, rendered by lang files.
            $table->string('priority_key', 10)->default('medium');
            // Workflow state: planned / in_progress / done / on_hold.
            $table->string('status_key', 15)->default('planned');
            // 0..100, the spreadsheet's 진행률 column.
            $table->unsignedSmallInteger('percent')->default(0);

            $table->foreignId('reporter_id')->nullable()->constrained('members')->nullOnDelete();
            // Denormalised primary assignee (Jira has exactly one); the extra people
            // sharing the row live in issue_assignees (the workbook allows "이성민, 정태훈").
            $table->foreignId('assignee_id')->nullable()->constrained('members')->nullOnDelete();

            $table->date('starts_on')->nullable();
            $table->date('due_on')->nullable();
            // "미정" (undecided) is a real value in the workbook, not a missing date.
            $table->boolean('due_undecided')->default(false);
            // 비고 — free text remark column.
            $table->string('note', 300)->nullable();

            // Board ordering inside a column (fractional ranking: 1.0, 2.0, ...).
            $table->decimal('board_rank', 20, 10)->default(1);
            $table->boolean('flagged')->default(false);
            $table->unsignedSmallInteger('story_points')->nullable();

            $table->timestamp('completed_at')->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->unique(['project_id', 'issue_no']);
            // Board: one project, one column, ordered.
            $table->index(['project_id', 'status_key', 'board_rank']);
            // Backlog / list views sorted by urgency.
            $table->index(['project_id', 'due_on']);
            $table->index(['assignee_id', 'status_key']);
            $table->index(['status_key', 'completed_at']);
        });

        // Co-assignees ("공동 담당"). The exporter joins these names with ", ".
        Schema::create('issue_assignees', function (Blueprint $table) {
            $table->id();
            $table->foreignId('issue_id')->constrained()->cascadeOnDelete();
            $table->foreignId('member_id')->constrained()->cascadeOnDelete();
            $table->unsignedSmallInteger('position')->default(0);

            $table->unique(['issue_id', 'member_id']);
            $table->index(['member_id', 'issue_id']);
        });

        Schema::create('issue_comments', function (Blueprint $table) {
            $table->id();
            $table->foreignId('issue_id')->constrained()->cascadeOnDelete();
            $table->foreignId('author_id')->nullable()->constrained('members')->nullOnDelete();
            // Markdown subset (bold, italic, code, links, @mentions), sanitised on render.
            $table->text('body');
            $table->timestamps();
            $table->softDeletes();

            $table->index(['issue_id', 'created_at']);
        });

        // Append-only audit trail powering the issue timeline panel.
        Schema::create('issue_activities', function (Blueprint $table) {
            $table->id();
            $table->foreignId('issue_id')->constrained()->cascadeOnDelete();
            $table->foreignId('actor_id')->nullable()->constrained('members')->nullOnDelete();
            // created | status_changed | percent_changed | assigned | commented | ...
            $table->string('verb', 30);
            // {"field":"status_key","from":"planned","to":"in_progress"}
            $table->jsonb('changes')->nullable();
            $table->timestamps();

            $table->index(['issue_id', 'created_at']);
            $table->index(['actor_id', 'created_at']);
        });

        Schema::create('issue_watchers', function (Blueprint $table) {
            $table->id();
            $table->foreignId('issue_id')->constrained()->cascadeOnDelete();
            $table->foreignId('member_id')->constrained()->cascadeOnDelete();
            $table->timestamps();

            $table->unique(['issue_id', 'member_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('issue_watchers');
        Schema::dropIfExists('issue_activities');
        Schema::dropIfExists('issue_comments');
        Schema::dropIfExists('issue_assignees');
        Schema::dropIfExists('issues');
    }
};
