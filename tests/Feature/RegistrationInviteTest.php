<?php

namespace Tests\Feature;

use App\Models\Admin;
use App\Models\RegistrationInvite;
use App\Models\User;
use App\Services\RegistrationInviteService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * Invite-only registration (app/Http/Controllers/Auth/RegistrationController.php).
 *
 * The application still has no public sign-up; what these tests pin is that the only
 * door is a code an administrator issued, that it is single use, and that it can be
 * taken back.
 */
class RegistrationInviteTest extends TestCase
{
    use RefreshDatabase;

    private function invite(array $attributes = []): array
    {
        $service = app(RegistrationInviteService::class);
        [$plain, $row] = $service->issue('테스트용', null);

        foreach ($attributes as $key => $value) {
            $row->forceFill([$key => $value])->save();
        }

        return [$plain, $row->fresh()];
    }

    public function test_a_valid_code_creates_an_account_and_signs_the_person_in(): void
    {
        [$plain] = $this->invite();

        $this->get('/register/'.$plain)->assertOk()->assertSee('Register');

        $response = $this->post('/register/'.$plain, [
            'name' => '채길용 사원',
            'username' => 'chae-gilyong',
            'password' => 'correct-horse-battery',
            'password_confirmation' => 'correct-horse-battery',
        ]);

        $response->assertRedirect(route('home'));

        $user = User::where('username', 'chae-gilyong')->firstOrFail();
        $this->assertSame('채길용 사원', $user->name);
        $this->assertTrue($user->isActive());
        $this->assertAuthenticatedAs($user, 'web');

        $invite = RegistrationInvite::firstOrFail();
        $this->assertNotNull($invite->used_at);
        $this->assertSame($user->id, $invite->used_by);
    }

    public function test_a_code_is_single_use(): void
    {
        [$plain] = $this->invite();

        $this->post('/register/'.$plain, [
            'name' => 'First',
            'username' => 'first-user',
            'password' => 'correct-horse-battery',
            'password_confirmation' => 'correct-horse-battery',
        ])->assertRedirect();

        auth('web')->logout();

        $this->post('/register/'.$plain, [
            'name' => 'Second',
            'username' => 'second-user',
            'password' => 'correct-horse-battery',
            'password_confirmation' => 'correct-horse-battery',
        ])->assertOk()->assertSee('cannot be used');

        $this->assertNull(User::where('username', 'second-user')->first());
    }

    public function test_expired_and_revoked_codes_are_refused(): void
    {
        [$expired] = $this->invite(['expires_at' => now()->subDay()]);
        [$revoked] = $this->invite(['revoked_at' => now()]);
        [$unknown] = ['sso_inv_doesnotexist'];

        foreach ([$expired, $revoked, $unknown] as $code) {
            $this->get('/register/'.$code)->assertOk()->assertSee('cannot be used');
        }
    }

    public function test_a_username_cannot_be_taken_twice(): void
    {
        User::create(['name' => 'Taken', 'username' => 'chae-gilyong', 'password' => 'x', 'status' => User::STATUS_ACTIVE]);
        [$plain] = $this->invite();

        $this->post('/register/'.$plain, [
            'name' => 'Another',
            'username' => 'chae-gilyong',
            'password' => 'correct-horse-battery',
            'password_confirmation' => 'correct-horse-battery',
        ])->assertSessionHasErrors('username');

        $this->assertSame(1, User::where('username', 'chae-gilyong')->count());
    }

    public function test_an_administrator_mints_and_revokes_a_code(): void
    {
        $admin = Admin::create([
            'name' => 'admin', 'email' => 'admin@test.local', 'password' => 'x', 'active' => true,
        ]);

        $this->actingAs($admin, 'admin')
            ->post('/admin/invites', ['note' => '채길용'])
            ->assertRedirect(route('admin.invites.index'))
            ->assertSessionHas('invite_url');

        $invite = RegistrationInvite::firstOrFail();
        $this->assertSame('채길용', $invite->note);

        $this->actingAs($admin, 'admin')
            ->delete('/admin/invites/'.$invite->id)
            ->assertRedirect(route('admin.invites.index'));

        $this->assertNotNull($invite->fresh()->revoked_at);
    }
}
