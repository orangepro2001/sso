<?php

namespace Tests\Unit;

use App\Http\Middleware\ConsoleSession;
use Illuminate\Http\Request;
use Tests\TestCase;

/**
 * The cookie-name switch for console paths.
 *
 * A unit test because the interesting part is pure: which paths get the separate
 * cookie. In a feature test the session driver is the array one, so no cookie is
 * ever emitted and the assertion would pass for the wrong reason.
 */
class ConsoleSessionTest extends TestCase
{
    /**
     * @return string the session cookie name in effect while handling $path
     */
    private function cookieNameFor(string $path, string $default = 'sso_session'): string
    {
        config(['session.cookie' => $default]);

        $seen = null;
        (new ConsoleSession)->handle(Request::create($path), function () use (&$seen) {
            $seen = (string) config('session.cookie');

            return response('ok');
        });

        return (string) $seen;
    }

    public function test_console_paths_use_the_console_cookie(): void
    {
        $this->assertSame(ConsoleSession::COOKIE, $this->cookieNameFor('/admin'));
        $this->assertSame(ConsoleSession::COOKIE, $this->cookieNameFor('/admin/login'));
        $this->assertSame(ConsoleSession::COOKIE, $this->cookieNameFor('/admin/devices/7'));
    }

    public function test_other_paths_keep_the_user_cookie(): void
    {
        foreach (['/login', '/', '/oauth/authorize', '/oauth/token', '/healthz', '/administrator'] as $path) {
            $this->assertSame(
                'sso_session',
                $this->cookieNameFor($path),
                'wrong cookie for '.$path,
            );
        }
    }

    public function test_the_switch_is_per_request(): void
    {
        $this->assertSame(ConsoleSession::COOKIE, $this->cookieNameFor('/admin'));
        // A plain request afterwards must not inherit the console cookie.
        $this->assertSame('sso_session', $this->cookieNameFor('/login'));
    }
}
