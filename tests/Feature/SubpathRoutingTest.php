<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * The service is mounted under /sso, so generated URLs must carry the prefix.
 *
 * Only one request per test: URL::forceRootUrl() is process-global, so the value
 * it installs leaks into the next request of the same test method. The prefix
 * rewriting logic itself is covered by Tests\Unit\PublicUrlRewriterTest.
 */
class SubpathRoutingTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config([
            'sso.force_root_url' => true,
            'sso.url_scheme' => 'https',
            'sso.session_path' => '/sso',
        ]);
    }

    private function withPublicHost(): static
    {
        return $this->withHeaders([
            'Host' => 'sso.test',
            'X-Forwarded-Proto' => 'https',
            'X-Forwarded-Host' => 'sso.test',
        ]);
    }

    public function test_the_user_login_form_posts_to_the_prefixed_path(): void
    {
        $this->withPublicHost()->get('/login')
            ->assertOk()
            ->assertSee('action="https://sso.test/sso/login"', false);
    }

    public function test_the_old_console_sign_in_link_goes_to_the_prefixed_user_sign_in(): void
    {
        $this->withPublicHost()->get('/admin/login')
            ->assertRedirect('https://sso.test/sso/login');
    }

    public function test_authenticated_console_pages_are_not_cacheable(): void
    {
        // A console page restored from the back/forward cache can carry links from
        // an older build; no-store keeps the browser honest.
        $admin = User::factory()->superAdmin()->create();
        $this->actingAs($admin, 'web');

        $response = $this->withPublicHost()->get('/admin/users');

        $response->assertOk();
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function test_the_sign_in_page_is_not_cacheable(): void
    {
        $response = $this->withPublicHost()->get('/login');

        $response->assertOk();
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function test_the_home_page_links_carry_the_prefix(): void
    {
        $this->withPublicHost()->get('/')
            ->assertOk()
            ->assertSee('https://sso.test/sso/login', false)
            ->assertSee('https://sso.test/sso/register', false);
    }
}
