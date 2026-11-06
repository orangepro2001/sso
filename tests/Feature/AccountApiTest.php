<?php

namespace Tests\Feature;

use App\Models\AccessToken;
use App\Models\OauthClient;
use App\Models\User;
use App\Services\TokenService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

/**
 * /api/me and /api/users (docs/api.md): called with the access token an application
 * got at sign-in, never with a session.
 */
class AccountApiTest extends TestCase
{
    use RefreshDatabase;

    private const PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

    private function tokenFor(User $user, array $scopes = ['openid', 'profile']): string
    {
        $client = OauthClient::factory()->create();

        return app(TokenService::class)->issueForUser($user, $client->client_id, $scopes)['access_token'];
    }

    private function api(string $token): static
    {
        return $this->withHeaders(['Authorization' => 'Bearer '.$token, 'Accept' => 'application/json']);
    }

    public function test_without_a_token_the_api_answers_401_json(): void
    {
        $this->getJson('/api/me')->assertStatus(401)->assertJsonPath('error', 'invalid_token')
            ->assertHeader('WWW-Authenticate');
        $this->withHeaders(['Authorization' => 'Bearer nonsense'])->getJson('/api/me')->assertStatus(401);
    }

    public function test_a_token_without_the_profile_scope_is_refused(): void
    {
        $user = User::factory()->create();
        $this->api($this->tokenFor($user, ['openid']))->getJson('/api/me')->assertStatus(403);
    }

    public function test_me_returns_the_account(): void
    {
        $user = User::factory()->create(['name' => '정태훈 대리', 'username' => 'tony', 'note' => 'secret note']);

        $this->api($this->tokenFor($user))->getJson('/api/me')
            ->assertOk()
            ->assertJsonPath('username', 'tony')
            ->assertJsonPath('name', '정태훈 대리')
            ->assertJsonPath('role', 'user')
            ->assertJsonPath('picture', null)
            ->assertJsonMissingPath('note');
    }

    public function test_a_disabled_user_loses_the_api_at_once(): void
    {
        $user = User::factory()->create();
        $token = $this->tokenFor($user);
        $user->forceFill(['status' => User::STATUS_DISABLED])->save();

        $this->api($token)->getJson('/api/me')->assertStatus(401);
    }

    public function test_a_person_renames_themselves(): void
    {
        $user = User::factory()->create(['username' => 'tony']);

        $this->api($this->tokenFor($user))->patchJson('/api/me', ['name' => '정태훈 과장', 'username' => 'hijack'])
            ->assertOk()->assertJsonPath('name', '정태훈 과장')->assertJsonPath('username', 'tony');

        $this->assertDatabaseHas('audit_logs', ['event' => 'user.profile.updated', 'subject_id' => (string) $user->id]);
    }

    public function test_a_person_uploads_and_removes_a_picture(): void
    {
        Storage::fake('local');
        $user = User::factory()->create();
        $token = $this->tokenFor($user);

        $response = $this->api($token)->post('/api/me/avatar', [
            'avatar' => UploadedFile::fake()->createWithContent('me.png', base64_decode(self::PNG)),
        ])->assertOk();

        $picture = (string) $response->json('picture');
        $this->assertStringStartsWith(rtrim((string) config('sso.issuer'), '/').'/avatar/'.$user->id.'/', $picture);
        Storage::disk('local')->assertExists($user->fresh()->avatar_path);

        // The URL actually serves the image, anonymously.
        $path = parse_url($picture, PHP_URL_PATH);
        $path = preg_replace('#^/sso#', '', (string) $path);
        $this->get($path.'?'.parse_url($picture, PHP_URL_QUERY))->assertOk()->assertHeader('Content-Type', 'image/png');

        $this->api($token)->deleteJson('/api/me/avatar')->assertOk()->assertJsonPath('picture', null);
    }

    public function test_a_picture_must_be_an_image(): void
    {
        $user = User::factory()->create();

        $this->api($this->tokenFor($user))->post('/api/me/avatar', [
            'avatar' => UploadedFile::fake()->create('notes.pdf', 10, 'application/pdf'),
        ])->assertStatus(422)->assertJsonValidationErrors('avatar');
    }

    public function test_changing_the_password_keeps_the_calling_token_and_revokes_the_rest(): void
    {
        $user = User::factory()->create(['password' => 'old-one']);
        $other = $this->tokenFor($user);
        $mine = $this->tokenFor($user);

        $this->api($mine)->putJson('/api/me/password', ['current_password' => 'wrong', 'password' => 'new-one'])
            ->assertStatus(422)->assertJsonValidationErrors('current_password');

        $this->api($mine)->putJson('/api/me/password', ['current_password' => 'old-one', 'password' => 'new-one'])->assertOk();

        $this->assertTrue(Hash::check('new-one', $user->fresh()->password));
        $this->api($mine)->getJson('/api/me')->assertOk();
        $this->api($other)->getJson('/api/me')->assertStatus(401);
    }

    public function test_an_ordinary_user_cannot_reach_user_management(): void
    {
        $user = User::factory()->create();
        $this->api($this->tokenFor($user))->getJson('/api/users')->assertStatus(403);
    }

    public function test_an_admin_lists_and_filters_users(): void
    {
        $admin = User::factory()->superAdmin()->create(['name' => 'Boss']);
        User::factory()->create(['name' => '이성민 팀장', 'username' => 'lee']);
        User::factory()->disabled()->create(['name' => 'Gone', 'username' => 'gone']);
        $token = $this->tokenFor($admin);

        $this->api($token)->getJson('/api/users')->assertOk()->assertJsonCount(3, 'data')->assertJsonPath('meta.total', 3);
        $this->api($token)->getJson('/api/users?q=성민')->assertOk()->assertJsonCount(1, 'data')->assertJsonPath('data.0.username', 'lee');
        $this->api($token)->getJson('/api/users?status=disabled')->assertOk()->assertJsonCount(1, 'data');
        $this->api($token)->getJson('/api/users?role=super_admin')->assertOk()->assertJsonPath('data.0.note', $admin->note);
    }

    public function test_an_admin_creates_a_user_and_gets_the_generated_password_once(): void
    {
        $admin = User::factory()->superAdmin()->create();
        $token = $this->tokenFor($admin);

        $response = $this->api($token)->postJson('/api/users', ['name' => '신입', 'username' => 'New.Person'])
            ->assertCreated()->assertJsonPath('username', 'new.person');

        $plain = (string) $response->json('generated_password');
        $this->assertSame(12, strlen($plain));
        $this->assertTrue(Hash::check($plain, User::query()->where('username', 'new.person')->value('password')));

        $this->api($token)->postJson('/api/users', ['name' => 'dup', 'username' => 'new.person'])
            ->assertStatus(422)->assertJsonValidationErrors('username');
    }

    public function test_an_admin_changes_role_status_and_password(): void
    {
        $admin = User::factory()->superAdmin()->create();
        $user = User::factory()->create();
        $token = $this->tokenFor($admin);
        $victimToken = $this->tokenFor($user);

        $this->api($token)->patchJson("/api/users/{$user->id}", ['role' => 'super_admin'])->assertOk()->assertJsonPath('role', 'super_admin');
        $this->api($token)->patchJson("/api/users/{$user->id}", ['status' => 'disabled'])->assertOk()->assertJsonPath('status', 'disabled');
        $this->assertNotNull(AccessToken::query()->where('user_id', $user->id)->value('revoked_at'));
        $this->api($victimToken)->getJson('/api/me')->assertStatus(401);

        $plain = $this->api($token)->postJson("/api/users/{$user->id}/password")->assertOk()->json('password');
        $this->assertTrue(Hash::check($plain, $user->fresh()->password));

        $this->api($token)->postJson("/api/users/{$user->id}/reset-link")->assertOk()
            ->assertJsonStructure(['url', 'expires_at']);
    }

    public function test_the_last_admin_and_the_caller_are_protected(): void
    {
        $admin = User::factory()->superAdmin()->create();
        $token = $this->tokenFor($admin);

        $this->api($token)->patchJson("/api/users/{$admin->id}", ['role' => 'user'])
            ->assertStatus(422)->assertJsonValidationErrors('role');
        $this->api($token)->patchJson("/api/users/{$admin->id}", ['status' => 'disabled'])
            ->assertStatus(422)->assertJsonValidationErrors('status');
        $this->api($token)->deleteJson("/api/users/{$admin->id}")->assertStatus(422);
        $this->assertTrue($admin->fresh()->isSuperAdmin());
    }

    public function test_an_admin_deletes_a_user(): void
    {
        $admin = User::factory()->superAdmin()->create();
        $user = User::factory()->create();
        $this->tokenFor($user);

        $this->api($this->tokenFor($admin))->deleteJson("/api/users/{$user->id}")->assertNoContent();

        $this->assertNull($user->fresh());
        $this->assertSame(0, AccessToken::query()->where('user_id', $user->id)->count());
        $this->assertDatabaseHas('audit_logs', ['event' => 'admin.user.deleted', 'subject_id' => (string) $user->id]);
    }
}
