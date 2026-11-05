<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AccessToken;
use App\Models\AuditLog;
use App\Models\BlacklistEntry;
use App\Models\GuestDevice;
use App\Models\OauthClient;
use App\Models\RefreshToken;
use App\Models\SigningKey;
use App\Models\User;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    public function __invoke(): View
    {
        return view('admin.dashboard', [
            'stats' => [
                'users' => User::query()->count(),
                'usersActive' => User::query()->where('status', User::STATUS_ACTIVE)->count(),
                'clients' => OauthClient::query()->where('active', true)->count(),
                'devices' => GuestDevice::query()->count(),
                'devicesBlacklisted' => GuestDevice::query()->where('status', GuestDevice::STATUS_BLACKLISTED)->count(),
                'tokensLive' => AccessToken::query()
                    ->whereNull('revoked_at')
                    ->where(fn ($q) => $q->whereNull('expires_at')->orWhere('expires_at', '>', now()))
                    ->count(),
                'refreshFamilies' => RefreshToken::query()->distinct()->count('family_id'),
                'blacklist' => BlacklistEntry::query()->count(),
            ],
            'recentDevices' => GuestDevice::query()->latest('last_seen_at')->limit(8)->get(),
            'recentAudit' => AuditLog::query()->latest('id')->limit(15)->get(),
            'guestSecretConfigured' => (string) config('sso.guest.secret', '') !== '',
            'keyCount' => SigningKey::query()->count(),
            // Moved off the public home page: whoever needs the endpoint list is
            // looking at the console, already signed in.
            'guestEnabled' => (bool) config('sso.guest.enabled', true),
            'guestAlgo' => (string) config('sso.guest.algo', 'hmac-sha256'),
            'endpoints' => $this->endpoints(),
        ]);
    }

    /**
     * Every address a client needs, built from the configured issuer so the console
     * cannot drift from what the discovery document publishes.
     *
     * @return array<string,string>
     */
    private function endpoints(): array
    {
        $issuer = rtrim((string) config('sso.issuer'), '/');

        return [
            'Issuer' => $issuer,
            'Discovery' => $issuer.'/.well-known/openid-configuration',
            'Authorize' => $issuer.'/oauth/authorize',
            'Token' => $issuer.'/oauth/token',
            'Userinfo' => $issuer.'/oauth/userinfo',
            'Introspect' => $issuer.'/oauth/introspect',
            'Revoke' => $issuer.'/oauth/revoke',
            'Guest' => $issuer.'/oauth/guest',
            'JWKS' => $issuer.'/.well-known/jwks.json',
        ];
    }

    public function audit(Request $request): View
    {
        $event = trim((string) $request->query('event', ''));

        $logs = AuditLog::query()
            ->when($event !== '', fn ($q) => $q->where('event', 'like', $event.'%'))
            ->latest('id')
            ->paginate(50)
            ->withQueryString();

        return view('admin.audit', [
            'logs' => $logs,
            'event' => $event,
        ]);
    }
}
