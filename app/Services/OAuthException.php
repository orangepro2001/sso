<?php

namespace App\Services;

use Illuminate\Http\JsonResponse;
use RuntimeException;

/**
 * An OAuth 2.0 / OIDC error (RFC 6749 §5.2, RFC 7009 §2.2.1).
 */
class OAuthException extends RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $description,
        public readonly int $status = 400,
        public readonly ?string $errorUri = null,
    ) {
        parent::__construct($description);
    }

    public static function invalidRequest(string $description): self
    {
        return new self('invalid_request', $description, 400);
    }

    public static function invalidClient(string $description = 'Client authentication failed'): self
    {
        return new self('invalid_client', $description, 401);
    }

    public static function invalidGrant(string $description): self
    {
        return new self('invalid_grant', $description, 400);
    }

    public static function unauthorizedClient(string $description): self
    {
        return new self('unauthorized_client', $description, 400);
    }

    public static function unsupportedGrantType(string $description): self
    {
        return new self('unsupported_grant_type', $description, 400);
    }

    public static function invalidScope(string $description): self
    {
        return new self('invalid_scope', $description, 400);
    }

    public static function accessDenied(string $description = 'The resource owner denied the request'): self
    {
        return new self('access_denied', $description, 403);
    }

    public static function serverError(string $description): self
    {
        return new self('server_error', $description, 500);
    }

    public function toJsonResponse(): JsonResponse
    {
        $body = ['error' => $this->errorCode, 'error_description' => $this->getMessage()];
        if ($this->errorUri !== null) {
            $body['error_uri'] = $this->errorUri;
        }

        return new JsonResponse($body, $this->status, ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache']);
    }
}
