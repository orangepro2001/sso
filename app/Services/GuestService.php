<?php

namespace App\Services;

use App\Models\GuestDevice;
use Illuminate\Http\Request;

/**
 * The silent guest channel.
 *
 * A client identifies itself with a stable environment value (hostname, machine
 * id, serial number) and proves it with HMAC-SHA256 over
 * "sso-guest-v1\n<device_id>" keyed by the shared SSO_GUEST_SECRET.
 *
 * Policy, as specified: every syntactically valid request is approved at once and
 * a usable token is returned, even when it looks suspicious. A malformed or
 * unsigned request is still served but flagged. Only an explicit administrator
 * blacklist refuses service. Review happens after the fact, never in the path.
 */
class GuestService
{
    public const SIG_PREFIX_ENV = 'SSO_GUEST_SECRET';

    public function __construct(
        private readonly TokenService $tokens,
        private readonly BlacklistService $blacklist,
        private readonly AuditLogger $audit,
    ) {}

    public function algorithm(): string
    {
        return (string) config('sso.guest.algo', 'hmac-sha256');
    }

    /**
     * The canonical signature for a device id, using the configured secret.
     */
    public function sign(string $deviceId): string
    {
        return hash_hmac('sha256', $this->signedPayload($deviceId), (string) config('sso.guest.secret', ''));
    }

    public function signedPayload(string $deviceId): string
    {
        return config('sso.guest.prefix', 'sso-guest-v1')."\n".$deviceId;
    }

    public function verify(string $deviceId, ?string $signature): bool
    {
        $secret = (string) config('sso.guest.secret', '');
        if ($secret === '' || ! is_string($signature) || $signature === '') {
            return false;
        }

        $expected = $this->sign($deviceId);

        return hash_equals($expected, strtolower(trim($signature)));
    }

    /**
     * Enrol (first sight) or touch an existing device and mint a token.
     *
     * @return array{device: GuestDevice, token: array<string, mixed>, signature_valid: bool, first_seen: bool}
     *
     * @throws OAuthException only when the device is blacklisted
     */
    public function authorize(string $deviceId, ?string $signature, Request $request): array
    {
        if ($this->blacklist->isDeviceBlocked($deviceId)) {
            $this->audit->log('guest.refused', 'guest', $deviceId, 'device', $deviceId, [
                'reason' => 'blacklisted', 'path' => $request->path(),
            ], $request);

            throw new OAuthException('access_denied', 'This device has been blacklisted', 403);
        }

        $signatureValid = $this->verify($deviceId, $signature);
        $ip = $this->audit->ip($request);
        $agent = $this->audit->agent($request);

        $device = GuestDevice::query()->where('device_id', $deviceId)->first();
        $firstSeen = $device === null;

        if ($device === null) {
            $device = GuestDevice::create([
                'device_id' => $deviceId,
                'status' => GuestDevice::STATUS_ACTIVE,
                'request_count' => 1,
                'first_seen_ip' => $ip,
                'last_seen_ip' => $ip,
                'first_user_agent' => $agent,
                'last_user_agent' => $agent,
                'first_seen_at' => now(),
                'last_seen_at' => now(),
            ]);
        } else {
            $device->forceFill([
                'request_count' => $device->request_count + 1,
                'last_seen_ip' => $ip,
                'last_seen_at' => now(),
                'last_user_agent' => $agent,
            ])->save();
        }

        $scopes = array_values(array_filter(explode(' ', (string) config('sso.guest.scope', 'db:read'))));
        $token = $this->tokens->issueForGuest($device, $scopes, $request);

        $this->audit->log($firstSeen ? 'guest.enrolled' : 'guest.reused', 'guest', $deviceId, 'device', $deviceId, [
            'signature_valid' => $signatureValid,
            'ip' => $ip,
            'suspicious' => ! $signatureValid,
        ], $request);

        return [
            'device' => $device,
            'token' => $token,
            'signature_valid' => $signatureValid,
            'first_seen' => $firstSeen,
        ];
    }
}
