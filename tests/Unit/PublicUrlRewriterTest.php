<?php

namespace Tests\Unit;

use App\Services\PublicUrlRewriter;
use PHPUnit\Framework\TestCase;

/**
 * The mounted-under-a-prefix URL handling, tested without a request cycle.
 *
 * This is the logic that decides whether a validation-failure redirect survives
 * the reverse proxy, so it is worth testing directly: the middleware that uses it
 * cannot be asserted on twice in one PHPUnit test because URL::forceRootUrl() is
 * process-global.
 */
class PublicUrlRewriterTest extends TestCase
{
    private function rewriter(string $prefix = 'sso', string $scheme = 'https'): PublicUrlRewriter
    {
        return new PublicUrlRewriter($scheme, $prefix);
    }

    public function test_the_public_root_carries_the_mount_point(): void
    {
        $this->assertSame('https://sso.test/sso', $this->rewriter()->root('sso.test'));
        $this->assertSame('http://127.0.0.1:3550', $this->rewriter('', 'http')->root('127.0.0.1:3550'));
    }

    public function test_a_prefixless_url_gets_the_mount_point(): void
    {
        $this->assertSame(
            'https://sso.test/sso/admin/login',
            $this->rewriter()->prefix('https://sso.test/admin/login'),
        );
    }

    public function test_an_already_prefixed_url_is_left_alone(): void
    {
        $url = 'https://sso.test/sso/admin/login';
        $this->assertSame($url, $this->rewriter()->prefix($url));

        // The mount point itself, with and without a trailing slash.
        $this->assertSame('https://sso.test/sso', $this->rewriter()->prefix('https://sso.test/sso'));
        $this->assertSame('https://sso.test/sso/', $this->rewriter()->prefix('https://sso.test/sso/'));
    }

    public function test_a_similar_prefix_is_not_mistaken_for_the_mount_point(): void
    {
        // "/ssox/..." must still be rewritten, otherwise a look-alike path escapes.
        $this->assertSame(
            'https://sso.test/sso/ssox/login',
            $this->rewriter()->prefix('https://sso.test/ssox/login'),
        );
    }

    public function test_query_strings_and_ports_survive(): void
    {
        $this->assertSame(
            'https://sso.test/sso/oauth/authorize?client_id=abc&scope=openid',
            $this->rewriter()->prefix('https://sso.test/oauth/authorize?client_id=abc&scope=openid'),
        );

        $this->assertSame(
            'http://127.0.0.1:3550/sso/login?next=%2Fadmin',
            $this->rewriter('sso', 'http')->prefix('http://127.0.0.1:3550/login?next=%2Fadmin'),
        );
    }

    public function test_the_scheme_is_normalised_to_the_configured_one(): void
    {
        // Behind the TLS terminator the app speaks http, clients see https.
        $this->assertSame(
            'https://sso.test/sso/login',
            $this->rewriter()->prefix('http://sso.test/login'),
        );
    }

    public function test_a_relative_or_opaque_value_is_returned_untouched(): void
    {
        foreach (['/admin/login', '', 'not a url', 'mailto:a@b.test'] as $value) {
            $this->assertSame($value, $this->rewriter()->prefix($value), 'changed: '.$value);
        }
    }

    public function test_an_empty_prefix_never_rewrites(): void
    {
        $url = 'https://sso.test/admin/login';
        $this->assertSame($url, $this->rewriter('')->prefix($url));
    }
}
