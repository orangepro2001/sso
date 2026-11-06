<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    /**
     * The console opens on the people it manages. The old status board (signing
     * keys, guest devices, endpoint list) answered questions nobody here asks.
     */
    public function __invoke(): RedirectResponse
    {
        return redirect()->route('admin.users.index');
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
