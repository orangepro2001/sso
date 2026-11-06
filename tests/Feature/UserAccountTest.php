<?php

namespace Tests\Feature;

use App\Models\AccessToken;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * The account page a normal user owns (app/Http/Controllers/Auth/ProfileController).
 *
 * The line these tests draw: a person may change their own display name and password,
 * and may sign other devices out; the username changes only with the current password.
 */
class UserAccountTest extends TestCase
{
    use RefreshDatabase;

    private function user(array $attributes = []): User
    {
        return User::create($attributes + [
            'name' => '채길용 사원',
            'username' => 'chae-gilyong',
            'password' => 'correct-horse-battery',
            'status' => User::STATUS_ACTIVE,
        ]);
    }

    public function test_the_page_needs_a_signed_in_user(): void
    {
        $this->get('/account')->assertRedirect(route('login'));
    }

    public function test_a_person_can_change_their_own_display_name(): void
    {
        $user = $this->user();

        $this->actingAs($user, 'web')
            ->put('/account', ['name' => '채길용 (품질)'])
            ->assertRedirect();

        $this->assertSame('채길용 (품질)', $user->fresh()->name);
        // Without the username field, the username stays as it is.
        $this->assertSame('chae-gilyong', $user->fresh()->username);
    }

    public function test_a_password_change_requires_the_current_one(): void
    {
        $user = $this->user();

        $this->actingAs($user, 'web')
            ->post('/account/password', [
                'current_password' => 'not-my-password',
                'password' => 'another-quite-long-password',
                'password_confirmation' => 'another-quite-long-password',
            ])
            ->assertSessionHasErrors('current_password');

        $this->assertTrue(Hash::check('correct-horse-battery', $user->fresh()->password));
    }

    public function test_a_password_change_revokes_other_devices(): void
    {
        $user = $this->user();

        $token = AccessToken::create([
            'kind' => AccessToken::KIND_JWT,
            'jti' => (string) Str::uuid(),
            'subject_type' => AccessToken::SUBJECT_USER,
            'user_id' => $user->id,
            'scopes' => ['openid'],
            'expires_at' => now()->addDay(),
        ]);

        $this->actingAs($user, 'web')
            ->post('/account/password', [
                'current_password' => 'correct-horse-battery',
                'password' => 'another-quite-long-password',
                'password_confirmation' => 'another-quite-long-password',
            ])
            ->assertRedirect();

        $this->assertTrue(Hash::check('another-quite-long-password', $user->fresh()->password));
        $this->assertNotNull($token->fresh()->revoked_at);
    }

    public function test_signing_out_everywhere_revokes_tokens(): void
    {
        $user = $this->user();

        $token = AccessToken::create([
            'kind' => AccessToken::KIND_JWT,
            'jti' => (string) Str::uuid(),
            'subject_type' => AccessToken::SUBJECT_USER,
            'user_id' => $user->id,
            'scopes' => ['openid'],
            'expires_at' => now()->addDay(),
        ]);

        $this->actingAs($user, 'web')->delete('/account/tokens')->assertRedirect();

        $this->assertNotNull($token->fresh()->revoked_at);
    }

    public function test_changing_the_username_needs_the_current_password(): void
    {
        $user = $this->user();

        $this->actingAs($user, 'web')
            ->put('/account', ['name' => $user->name, 'username' => 'renamed'])
            ->assertSessionHasErrors('current_password');
        $this->assertSame('chae-gilyong', $user->fresh()->username);

        $this->put('/account', ['name' => $user->name, 'username' => 'renamed', 'current_password' => 'correct-horse-battery'])
            ->assertSessionHasNoErrors();
        $this->assertSame('renamed', $user->fresh()->username);
    }

    public function test_a_picture_can_be_uploaded_and_removed(): void
    {
        Storage::fake('local');
        $user = $this->user();

        $this->actingAs($user, 'web')
            ->post('/account/avatar', ['avatar' => UploadedFile::fake()->createWithContent('me.png', base64_decode(self::PNG))])
            ->assertSessionHasNoErrors();

        $user->refresh();
        $this->assertNotNull($user->avatar_path);
        Storage::disk('local')->assertExists($user->avatar_path);
        $this->assertStringStartsWith(rtrim((string) config('sso.issuer'), '/').'/avatar/'.$user->id.'/', (string) $user->avatarUrl());

        $this->delete('/account/avatar')->assertSessionHasNoErrors();
        $this->assertNull($user->fresh()->avatar_path);
    }

    public function test_the_account_page_renders_in_korean(): void
    {
        $this->actingAs($this->user(), 'web')->get('/account')->assertOk()->assertSee('프로필 사진')->assertSee('비밀번호 변경');
    }

    /** A 1×1 transparent PNG. */
    private const PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
}
