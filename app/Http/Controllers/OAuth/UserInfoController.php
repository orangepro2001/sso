<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Models\AccessToken;
use App\Models\User;
use App\Services\TokenService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * GET /oauth/userinfo — bearer-protected identity document (OIDC §5.3).
 */
class UserInfoController extends Controller
{
    public function __construct(private readonly TokenService $tokens) {}

    public function __invoke(Request $request): JsonResponse
    {
        $plain = $this->bearer($request);
        if ($plain === null) {
            return $this->unauthorized('Missing bearer token');
        }

        $record = $this->tokens->resolve($plain);
        if ($record === null) {
            return $this->unauthorized('Invalid or expired token');
        }

        $scopes = $record->scopes ?? [];

        if ($record->subject_type === AccessToken::SUBJECT_GUEST) {
            return response()->json([
                'sub' => 'guest:'.$record->guestDevice?->device_id,
                'subject_type' => 'guest',
                'device_id' => $record->guestDevice?->device_id,
                'scope' => implode(' ', $scopes),
            ]);
        }

        if ($record->subject_type === AccessToken::SUBJECT_CLIENT) {
            return response()->json([
                'sub' => 'client:'.$record->client_id,
                'subject_type' => 'client',
                'scope' => implode(' ', $scopes),
            ]);
        }

        /** @var User|null $user */
        $user = $record->user;
        if ($user === null) {
            return $this->unauthorized('Unknown subject');
        }

        $body = ['sub' => (string) $user->id, 'subject_type' => 'user', 'scope' => implode(' ', $scopes)];
        if (in_array('profile', $scopes, true)) {
            $body['name'] = $user->name;
            $body['preferred_username'] = $user->username;
            // Relying parties decide what a super administrator may do in their own
            // application (work-report: edit anybody's issue).
            $body['role'] = $user->role;
            $body['created_at'] = $user->created_at?->getTimestamp();

            // Signed URL rather than a session-protected one: the relying party reads
            // this server-side and has no session to offer (User::avatarUrl).
            if ($user->hasAvatar()) {
                $body['picture'] = $user->avatarUrl();
            }
        }

        return response()->json($body);
    }

    private function bearer(Request $request): ?string
    {
        $header = (string) $request->header('Authorization', '');
        if (preg_match('/^Bearer\s+(\S+)$/i', $header, $m) === 1) {
            return $m[1];
        }

        $fallback = $request->input('access_token');

        return is_string($fallback) && $fallback !== '' ? $fallback : null;
    }

    private function unauthorized(string $message): JsonResponse
    {
        return response()->json(['error' => 'invalid_token', 'error_description' => $message], 401, [
            'WWW-Authenticate' => 'Bearer error="invalid_token", error_description="'.$message.'"',
        ]);
    }
}
