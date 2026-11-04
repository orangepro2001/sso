<?php

namespace App\Services;

/**
 * URL rewriting for a service mounted under a path prefix.
 *
 * caddy strips "/sso" before forwarding, so the framework sees "/admin/login"
 * while clients must see "/sso/admin/login". Pure string handling, kept out of the
 * middleware so it can be tested without booting a request cycle.
 */
final class PublicUrlRewriter
{
    public function __construct(
        private readonly string $schemeValue,
        private readonly string $pathPrefix,
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            (string) config('sso.url_scheme', 'https'),
            trim((string) config('sso.session_path', '/sso'), '/'),
        );
    }

    public function scheme(): string
    {
        return $this->schemeValue;
    }

    public function root(string $host): string
    {
        return $this->schemeValue.'://'.$host.($this->pathPrefix === '' ? '' : '/'.$this->pathPrefix);
    }

    /**
     * Insert the mount point between the origin and the path, when it is missing.
     * Anything that does not look like an absolute URL is returned untouched.
     */
    public function prefix(string $url): string
    {
        if ($this->pathPrefix === '') {
            return $url;
        }

        $parts = parse_url($url);
        if ($parts === false || ! isset($parts['host'])) {
            return $url;
        }

        $path = $parts['path'] ?? '/';
        if ($this->hasPrefix($path)) {
            return $url;
        }

        $port = isset($parts['port']) ? ':'.$parts['port'] : '';
        $query = isset($parts['query']) && $parts['query'] !== '' ? '?'.$parts['query'] : '';

        return $this->schemeValue.'://'.$parts['host'].$port.'/'.$this->pathPrefix.$path.$query;
    }

    public function hasPrefix(string $path): bool
    {
        return $path === '/'.$this->pathPrefix || str_starts_with($path, '/'.$this->pathPrefix.'/');
    }
}
