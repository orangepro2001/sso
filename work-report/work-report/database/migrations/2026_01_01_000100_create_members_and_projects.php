<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * People and the project skeleton.
 *
 * There is no login yet (docs/auth-seam.md): `members` is what an OIDC subject
 * will be attached to later, so everything that references a human references
 * this table and nothing has to change when authentication arrives.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('members', function (Blueprint $table) {
            $table->id();
            // Stable handle used across imports and, later, as the SSO subject link.
            $table->string('key', 40)->unique();
            $table->string('name', 80);
            $table->string('email', 190)->nullable()->unique();
            // Department / team label shown in the report header (e.g. 검사 기술).
            $table->string('department', 120)->nullable();
            $table->string('title', 120)->nullable();
            // Reporting line: who receives this member's daily report.
            $table->foreignId('reports_to_id')->nullable()->constrained('members')->nullOnDelete();
            $table->string('color', 7)->default('#2F5597');
            $table->unsignedSmallInteger('position')->default(0);
            $table->boolean('active')->default(true);
            $table->timestamps();

            $table->index(['active', 'position']);
        });

        Schema::create('projects', function (Blueprint $table) {
            $table->id();
            // The Excel "구분" bucket: 3D AFVI / 2D AFVI / 기타 / 목표.
            $table->string('name', 80);
            // Short prefix that forms the issue key: "3D" -> 3D-01.
            $table->string('abbr', 12);
            $table->string('color', 7)->default('#2F5597');
            $table->string('description', 500)->nullable();
            $table->unsignedSmallInteger('position')->default(0);
            $table->boolean('archived')->default(false);
            $table->timestamps();

            $table->unique('abbr');
            $table->index(['archived', 'position']);
        });

        Schema::create('project_members', function (Blueprint $table) {
            $table->id();
            $table->foreignId('project_id')->constrained()->cascadeOnDelete();
            $table->foreignId('member_id')->constrained()->cascadeOnDelete();
            // Mirrors Jira's project roles; only 'member' and 'lead' matter today.
            $table->string('role', 20)->default('member');
            $table->timestamps();

            $table->unique(['project_id', 'member_id']);
        });

        Schema::create('sprints', function (Blueprint $table) {
            $table->id();
            $table->foreignId('project_id')->constrained()->cascadeOnDelete();
            $table->string('name', 120);
            $table->string('goal', 500)->nullable();
            // planned | active | closed
            $table->string('state', 12)->default('planned');
            $table->date('starts_on')->nullable();
            $table->date('ends_on')->nullable();
            $table->unsignedSmallInteger('position')->default(0);
            $table->timestamps();

            $table->index(['project_id', 'state']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sprints');
        Schema::dropIfExists('project_members');
        Schema::dropIfExists('projects');
        Schema::dropIfExists('members');
    }
};
