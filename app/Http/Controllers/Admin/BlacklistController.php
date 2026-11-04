<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\BlacklistEntry;
use App\Services\AuditLogger;
use App\Services\BlacklistService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

/**
 * Hard deny list, independent of a device row: useful for a stolen token (jti),
 * a compromised user account, or a client that must be shut down.
 */
class BlacklistController extends Controller
{
    public function __construct(
        private readonly AuditLogger $audit,
        private readonly BlacklistService $blacklist,
    ) {}

    public function index(): View
    {
        return view('admin.blacklist.index', [
            'entries' => \App\Models\BlacklistEntry::query()->latest('id')->paginate(50),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'kind' => ['required', Rule::in([
                \App\Models\BlacklistEntry::KIND_DEVICE,
                \App\Models\BlacklistEntry::KIND_USER,
                \App\Models\BlacklistEntry::KIND_TOKEN,
                \App\Models\BlacklistEntry::KIND_CLIENT,
            ])],
            'value' => ['required', 'string', 'max:191'],
            'reason' => ['nullable', 'string', 'max:500'],
        ]);

        $this->blacklist->block($data['kind'], $data['value'], $data['reason'] ?? null, Auth::guard('admin')->id());

        $this->audit->log('admin.blacklist.added', 'admin', Auth::guard('admin')->id(), $data['kind'], $data['value'], [
            'reason' => $data['reason'] ?? null,
        ], $request);

        return redirect()->route('admin.blacklist.index')->with('status', 'Entry added.');
    }

    public function destroy(Request $request, \App\Models\BlacklistEntry $entry): RedirectResponse
    {
        $this->audit->log('admin.blacklist.removed', 'admin', Auth::guard('admin')->id(), $entry->kind, $entry->value, [], $request);
        $entry->delete();

        return redirect()->route('admin.blacklist.index')->with('status', 'Entry removed.');
    }
}
