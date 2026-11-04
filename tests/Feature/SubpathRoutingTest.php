<?php

namespace Tests\Feature;

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

    public function test_the_admin_login_form_posts_to_the_prefixed_path(): void
    {
        $this->withPublicHost()->get('/admin/login')
            ->assertOk()
            ->assertSee('action="https://sso.test/sso/admin/login"', false);
    }

    public function test_the_home_page_links_carry_the_prefix(): void
    {
        $this->withPublicHost()->get('/')
            ->assertOk()
            ->assertSee('https://sso.test/sso/login', false)
            ->assertSee('https://sso.test/sso/admin/login', false);
    }
}
