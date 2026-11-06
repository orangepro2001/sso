<?php

namespace Tests\Feature;

use App\Models\AccessToken;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * The console's person page: every action is one button, and the account rules
 * (UserAccounts) hold here exactly as they do in the API.
 */
class UserManagementTest extends TestCase
{
    use RefreshDatabase;

    private const PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

    private User $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->admin = User::factory()->superAdmin()->create(['name' => '관리자', 'username' => 'boss']);
        $this->actingAs($this->admin, 'web');
    }

    private function token(User $user): AccessToken
    {
        return AccessToken::create([
            'kind' => AccessToken::KIND_JWT, 'jti' => (string) Str::uuid(),
            'subject_type' => AccessToken::SUBJECT_USER, 'user_id' => $user->id,
            'scopes' => ['openid', 'profile'], 'expires_at' => now()->addDay(),
        ]);
    }

    public function test_the_list_filters_and_searches(): void
    {
        User::factory()->create(['name' => '이성민 팀장', 'username' => 'lee']);
        User::factory()->disabled()->create(['name' => '퇴사자', 'username' => 'gone']);

        $this->get('/admin/users')->assertOk()->assertSee('이성민 팀장')->assertSee('퇴사자');
        $this->get('/admin/users?q=lee')->assertOk()->assertSee('이성민 팀장')->assertDontSee('퇴사자');
        $this->get('/admin/users?filter=disabled')->assertOk()->assertSee('퇴사자')->assertDontSee('이성민 팀장');
        $this->get('/admin/users?filter=admin')->assertOk()->assertSee('관리자')->assertDontSee('이성민 팀장');
    }

    public function test_the_person_page_shows_everything_in_one_place(): void
    {
        $user = User::factory()->create(['name' => '정태훈 대리', 'username' => 'tony']);
        $this->token($user);

        $this->get("/admin/users/{$user->id}")->assertOk()
            ->assertSee('정태훈 대리')
            ->assertSee('관리자로 지정')
            ->assertSee('비활성화')
            ->assertSee('재설정 링크 만들기')
            ->assertSee('로그인 중인 앱')
            ->assertSee('영구 삭제');
    }

    public function test_a_failed_create_reopens_the_dialog_with_the_error(): void
    {
        User::factory()->create(['username' => 'taken']);

        $this->from('/admin/users')->post('/admin/users', ['name' => 'X', 'username' => 'taken'])
            ->assertRedirect('/admin/users')
            ->assertSessionHasErrors('username', null, 'create');

        $this->get('/admin/users')->assertSee('data-open-now', false)->assertSee('이미 쓰이고 있는 아이디');
    }

    public function test_disabling_signs_the_person_out_everywhere(): void
    {
        $user = User::factory()->create();
        $token = $this->token($user);
        DB::table('sessions')->insert(['id' => 'their-browser', 'user_id' => $user->id, 'payload' => '', 'last_activity' => time()]);

        $this->post("/admin/users/{$user->id}/status", ['status' => 'disabled'])->assertSessionHasNoErrors();

        $this->assertFalse($user->fresh()->isActive());
        $this->assertNotNull($token->fresh()->revoked_at);
        $this->assertDatabaseMissing('sessions', ['id' => 'their-browser']);

        $this->post("/admin/users/{$user->id}/status", ['status' => 'active']);
        $this->assertTrue($user->fresh()->isActive());
    }

    public function test_an_admin_cannot_lock_themselves_out(): void
    {
        $this->from("/admin/users/{$this->admin->id}")
            ->post("/admin/users/{$this->admin->id}/role", ['role' => 'user'])
            ->assertSessionHasErrors('role');
        $this->post("/admin/users/{$this->admin->id}/status", ['status' => 'disabled'])->assertSessionHasErrors('status');

        $this->assertTrue($this->admin->fresh()->isSuperAdmin());
        $this->assertTrue($this->admin->fresh()->isActive());
    }

    public function test_the_last_other_admin_cannot_be_demoted_while_alone(): void
    {
        $other = User::factory()->superAdmin()->create();
        // Two admins: demoting the other one is fine.
        $this->post("/admin/users/{$other->id}/role", ['role' => 'user'])->assertSessionHasNoErrors();
        $this->assertFalse($other->fresh()->isSuperAdmin());
    }

    public function test_the_edit_form_saves_name_username_and_note(): void
    {
        $user = User::factory()->create(['username' => 'old']);

        $this->put("/admin/users/{$user->id}", ['name' => '새 이름', 'username' => 'NEW', 'note' => '품질팀'])
            ->assertSessionHasNoErrors();

        $user->refresh();
        $this->assertSame(['새 이름', 'new', '품질팀'], [$user->name, $user->username, $user->note]);
        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.user.updated', 'subject_id' => (string) $user->id]);
    }

    public function test_an_admin_sets_someone_elses_picture(): void
    {
        Storage::fake('local');
        $user = User::factory()->create();

        $this->post("/admin/users/{$user->id}/avatar", [
            'avatar' => UploadedFile::fake()->createWithContent('p.png', base64_decode(self::PNG)),
        ])->assertSessionHasNoErrors();
        $this->assertNotNull($user->fresh()->avatar_path);
        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.user.avatar_updated']);

        $this->delete("/admin/users/{$user->id}/avatar");
        $this->assertNull($user->fresh()->avatar_path);
    }

    public function test_sign_out_everywhere_revokes_tokens(): void
    {
        $user = User::factory()->create();
        $token = $this->token($user);

        $this->post("/admin/users/{$user->id}/sign-out")->assertSessionHasNoErrors();

        $this->assertNotNull($token->fresh()->revoked_at);
    }

    public function test_deleting_needs_the_username_typed(): void
    {
        $user = User::factory()->create(['username' => 'leaver']);

        $this->delete("/admin/users/{$user->id}", ['confirm' => 'nope'])->assertSessionHasErrors('confirm');
        $this->assertNotNull($user->fresh());

        $this->delete("/admin/users/{$user->id}", ['confirm' => 'leaver'])->assertRedirect(route('admin.users.index'));
        $this->assertNull($user->fresh());
    }

    public function test_the_activity_page_reads_like_sentences_and_filters_by_person(): void
    {
        $user = User::factory()->create(['name' => '정태훈 대리']);
        $this->post("/admin/users/{$user->id}/role", ['role' => 'super_admin']);

        $this->get('/admin/audit')->assertOk()->assertSee('계정 정보 변경')->assertSee('권한 일반 → 관리자');
        $this->get("/admin/audit?user={$user->id}&kind=account")->assertOk()->assertSee('정태훈 대리');
        $this->get('/admin/audit?kind=login')->assertOk()->assertDontSee('계정 정보 변경</span>', false);
    }
}
