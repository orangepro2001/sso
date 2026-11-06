<?php

namespace App\Http\Middleware;

use App\Models\AccessToken;
use App\Services\TokenService;
use App\Support\BearerToken;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The account API (routes/api.php) is called with the access token an application
 * received at sign-in: the same token /oauth/userinfo accepts, for the same person.
 *
 * `token` alone: any active user holding a token with the `profile` scope.
 * `token:admin`: additionally a super administrator — the console's rule.
 */
class AuthenticateToken
{
    public function __construct(private readonly TokenService $tokens) {}

    public function handle(Request $request, Closure $next, ?string $level = null): Response
    {
        $plain = BearerToken::from($request);
        $record = $plain === null ? null : $this->tokens->resolve($plain);

        if ($record === null || $record->subject_type !== AccessToken::SUBJECT_USER || $record->user === null) {
            return self::error(401, 'invalid_token', '토큰이 없거나 만료되었습니다. 다시 로그인하세요.');
        }

        if (! in_array('profile', $record->scopes ?? [], true)) {
            return self::error(403, 'insufficient_scope', '이 토큰에는 profile 범위가 없습니다.');
        }

        $user = $record->user;
        if ($level === 'admin' && ! $user->isSuperAdmin()) {
            return self::error(403, 'forbidden', '관리자만 사용할 수 있습니다.');
        }

        $request->setUserResolver(fn () => $user);
        $request->attributes->set('access_token', $record);

        return $next($request);
    }

    public static function error(int $status, string $code, string $message): JsonResponse
    {
        $headers = $status === 401
            ? ['WWW-Authenticate' => 'Bearer error="invalid_token"']
            : [];

        return response()->json(['error' => $code, 'message' => $message], $status, $headers);
    }
}
