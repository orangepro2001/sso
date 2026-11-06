<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use App\Support\AuditPresenter;
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

    /**
     * Activity, readable: filter by person and by kind, sentences instead of codes.
     */
    public function audit(Request $request): View
    {
        $category = (string) $request->query('kind', '');
        $prefixes = AuditPresenter::CATEGORIES[$category][1] ?? null;
        $person = $request->query('user');
        $person = is_string($person) && ctype_digit($person) ? User::query()->find((int) $person) : null;

        $logs = AuditLog::query()
            ->when($prefixes !== null, fn ($q) => $q->where(function ($w) use ($prefixes) {
                foreach ($prefixes as $prefix) {
                    $w->orWhere('event', 'like', $prefix.'%');
                }
            }))
            ->when($person !== null, fn ($q) => $q->where(fn ($w) => $w
                ->where(fn ($s) => $s->where('subject_type', 'user')->where('subject_id', (string) $person->id))
                ->orWhere(fn ($a) => $a->whereIn('actor_type', ['user', 'admin'])->where('actor_id', (string) $person->id))
                ->orWhere(fn ($a) => $a->where('actor_type', 'anonymous')->where('actor_id', $person->username))))
            ->latest('id')
            ->paginate(50)
            ->withQueryString();

        return view('admin.audit', [
            'logs' => $logs,
            'kind' => $prefixes === null ? '' : $category,
            'person' => $person,
            'people' => AuditPresenter::people($logs->getCollection()),
            'clients' => AuditPresenter::clients(),
            'everyone' => User::query()->orderBy('name')->get(['id', 'name', 'username']),
        ]);
    }
}
