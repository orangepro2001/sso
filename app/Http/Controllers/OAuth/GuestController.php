<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Controllers\Controller;
use App\Models\GuestDevice;
use App\Services\GuestService;
use App\Services\OAuthException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * POST /oauth/guest — the silent enrolment endpoint.
 *
 * The first request from a validly signed device is approved immediately and a
 * usable token comes back in the same response. Nothing is ever held for review,
 * which is the whole point: clients must work without a human in the loop.
 */
class GuestController extends Controller
{
    public function __construct(private readonly GuestService $guests) {}

    public function __invoke(Request $request): JsonResponse
    {
        if (! config('sso.guest.enabled', true)) {
            return response()->json([
                'error' => 'access_denied',
                'error_description' => 'The guest channel is disabled',
            ], 403);
        }

        $deviceId = $request->input('device_id');
        if (! is_string($deviceId) || trim($deviceId) === '') {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => 'device_id is required',
                'hint' => 'Send a stable environment value such as the hostname, machine-id or serial number.',
            ], 400);
        }

        $deviceId = trim($deviceId);
        if (strlen($deviceId) > 191) {
            return response()->json([
                'error' => 'invalid_request',
                'error_description' => 'device_id is too long (max 191 bytes)',
            ], 400);
        }

        $signature = $request->input('signature') ?? $request->header('X-SSO-Signature');
        $signature = is_string($signature) ? $signature : null;

        try {
            $result = $this->guests->authorize($deviceId, $signature, $request);
        } catch (OAuthException $e) {
            return $e->toJsonResponse();
        }

        return response()->json([
            'access_token' => $result['token']['access_token'],
            'token_type' => 'Bearer',
            'expires_in' => $result['token']['expires_in'],
            'scope' => $result['token']['scope'],
            'device_id' => $result['device']->device_id,
            'device_status' => $result['device']->status,
            'signature_valid' => $result['signature_valid'],
            'newly_enrolled' => $result['first_seen'],
            // Built from the issuer, not from the request, so the value is identical
            // no matter which proxy hop or bind address the call came through.
            'introspection_endpoint' => rtrim((string) config('sso.issuer'), '/').'/oauth/introspect',
        ])->withHeaders([
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }
}
