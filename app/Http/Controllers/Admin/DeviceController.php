<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AccessToken;
use App\Models\GuestDevice;
use App\Models\OauthClient;
use App\Services\AuditLogger;
use App\Services\BlacklistService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

/**
 * A posteriori review of silently enrolled guest devices.
 *
 * Devices are approved the moment they sign a valid request; a human looks at
 * this list and blacklists anything that should not be there.
 */
class DeviceController extends Controller
{
    public function __construct(
        private readonly AuditLogger $audit,
        private readonly BlacklistService $blacklist,
    ) {}

    public function index(Request $request): View
    {
        $status = (string) $request->query('status', 'all');
        $search = trim((string) $request->query('q', ''));

        $devices = GuestDevice::query()
            ->when($status !== 'all', fn ($q) => $q->where('status', $status))
            ->when($search !== '', fn ($q) => $q->where('device_id', 'ilike', '%'.$search.'%'))
            ->orderByDesc('last_seen_at')
            ->paginate(25)
            ->withQueryString();

        return view('admin.devices.index', [
            'devices' => $devices,
            'status' => $status,
            'search' => $search,
            'counts' => [
                'all' => GuestDevice::query()->count(),
                'active' => GuestDevice::query()->where('status', GuestDevice::STATUS_ACTIVE)->count(),
                'blacklisted' => GuestDevice::query()->where('status', GuestDevice::STATUS_BLACKLISTED)->count(),
                'unreviewed' => GuestDevice::query()->whereNull('reviewed_at')->count(),
            ],
        ]);
    }

    public function show(GuestDevice $device): View
    {
        return view('admin.devices.show', [
            'device' => $device,
            'tokens' => $device->tokens()->latest('id')->limit(25)->get(),
        ]);
    }

    public function block(Request $request, GuestDevice $device): RedirectResponse
    {
        $data = $request->validate([
            'reason' => ['nullable', 'string', 'max:500'],
        ]);

        $device->forceFill([
            'status' => GuestDevice::STATUS_BLACKLISTED,
            'reviewed_at' => now(),
            'reviewed_by' => Auth::guard('admin')->id(),
        ])->save();

        $this->blacklist->block(
            \App\Models\BlacklistEntry::KIND_DEVICE,
            $device->device_id,
            $data['reason'] ?? 'Device blacklisted from the console',
            Auth::guard('admin')->id(),
        );

        // Kill what is already out there so the decision takes effect immediately.
        $revoked = AccessToken::query()
            ->where('guest_device_id', $device->id)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);

        $this->audit->log('admin.device.blocked', 'admin', Auth::guard('admin')->id(), 'device', $device->device_id, [
            'reason' => $data['reason'] ?? null, 'tokens_revoked' => $revoked,
        ], $request);

        return redirect()->back()->with('status', "Device {$device->device_id} blacklisted; {$revoked} token(s) revoked.");
    }

    public function unblock(Request $request, GuestDevice $device): RedirectResponse
    {
        $device->forceFill([
            'status' => GuestDevice::STATUS_ACTIVE,
            'reviewed_at' => now(),
            'reviewed_by' => Auth::guard('admin')->id(),
        ])->save();

        $this->blacklist->unblock(\App\Models\BlacklistEntry::KIND_DEVICE, $device->device_id);

        $this->audit->log('admin.device.unblocked', 'admin', Auth::guard('admin')->id(), 'device', $device->device_id, [], $request);

        return redirect()->back()->with('status', "Device {$device->device_id} reinstated.");
    }

    public function review(Request $request, GuestDevice $device): RedirectResponse
    {
        $data = $request->validate([
            'note' => ['nullable', 'string', 'max:2000'],
            'verdict' => ['required', Rule::in(['ok'])],
        ]);

        $device->forceFill([
            'reviewed_at' => now(),
            'reviewed_by' => Auth::guard('admin')->id(),
            'note' => $data['note'] ?? $device->note,
        ])->save();

        $this->audit->log('admin.device.reviewed', 'admin', Auth::guard('admin')->id(), 'device', $device->device_id, [], $request);

        return redirect()->back()->with('status', "Device {$device->device_id} reviewed.");
    }
}
