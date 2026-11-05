<?php

namespace Tests\Feature;

use App\Models\AccessToken;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

/**
 * The account page a normal user owns (app/Http/Controllers/Auth/AccountController).
 *
 * The line these tests draw: a person may change their own display name and password,
 * and may sign other devices out — but not their username, which is the identity every
 * application matches on.
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
        // The username is not part of the form, so it cannot be smuggled in.
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
            'subject_type' => AccessToken::SUBJECT_USER,
            'user_id' => $user->id,
            'scopes' => ['openid'],
            'expires_at' => now()->addDay(),
        ]);

        $this->actingAs($user, 'web')->delete('/account/tokens')->assertRedirect();

        $this->assertNotNull($token->fresh()->revoked_at);
    }
}
