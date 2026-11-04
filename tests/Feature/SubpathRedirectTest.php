<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * The service is mounted under /sso, and every absolute URL it emits must carry
 * that prefix. Regression guard: redirects produced by validation failures and by
 * back() used to lose the prefix because the root URL was forced after the session
 * had already recorded the "previous" URL.
 */
class SubpathRedirectTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        // Turn the production behaviour back on for these tests only.
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

    public function test_a_failed_admin_login_redirects_back_under_the_prefix(): void
    {
        $response = $this->withPublicHost()->post('/admin/login', [
            'email' => 'ghost@example.test',
            'password' => 'wrong',
        ]);

        $response->assertRedirect();
        $this->assertStringStartsWith(
            'https://sso.test/sso',
            (string) $response->headers->get('Location'),
            'The redirect lost the /sso prefix: '.$response->headers->get('Location')
        );
    }

    public function test_a_failed_user_login_redirects_back_under_the_prefix(): void
    {
        $response = $this->withPublicHost()->post('/login', [
            'email' => 'ghost@example.test',
            'password' => 'wrong',
        ]);

        $response->assertRedirect();
        $this->assertStringStartsWith('https://sso.test/sso', (string) $response->headers->get('Location'));
    }

    public function test_generated_links_carry_the_prefix(): void
    {
        $this->withPublicHost()->get('/login')->assertOk();

        $this->assertSame('https://sso.test/sso/login', route('login'));
        $this->assertSame('https://sso.test/sso/admin/login', route('admin.login'));
        // route('home') is '/' under the forced root, i.e. the mount point itself.
        $this->assertSame('https://sso.test/sso', route('home'));
    }

    // URL::forceRootUrl() is process-global, so each assertion gets its own test
    // (and therefore its own freshly booted application).
    public function test_the_user_login_form_posts_to_the_prefixed_path(): void
    {
        $this->withPublicHost()->get('/login')
            ->assertSee('action="https://sso.test/sso/login"', false);
    }

    public function test_the_admin_login_form_posts_to_the_prefixed_path(): void
    {
        $this->withPublicHost()->get('/admin/login')
            ->assertSee('action="https://sso.test/sso/admin/login"', false);
    }

    public function test_an_unauthenticated_console_visit_redirects_under_the_prefix(): void
    {
        $response = $this->withPublicHost()->get('/admin/users');

        $response->assertRedirect();
        $this->assertStringStartsWith('https://sso.test/sso', (string) $response->headers->get('Location'));
    }
}
