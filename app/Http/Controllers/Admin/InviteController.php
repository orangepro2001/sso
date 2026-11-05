<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\RegistrationInvite;
use App\Services\AuditLogger;
use App\Services\RegistrationInviteService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

/**
 * Registration codes (app/Services/RegistrationInviteService).
 *
 * The console can mint one, hand out the URL, and take it back. The plaintext code
 * is shown exactly once, on the redirect after minting.
 */
class InviteController extends Controller
{
    public function __construct(
        private readonly RegistrationInviteService $invites,
        private readonly AuditLogger $audit,
    ) {}

    public function index(): View
    {
        return view('admin.invites.index', [
            'invites' => RegistrationInvite::query()
                ->with(['creator:id,name', 'user:id,name,username'])
                ->latest('id')
                ->paginate(25),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'note' => ['nullable', 'string', 'max:120'],
        ]);

        [$plain, $invite] = $this->invites->issue($data['note'] ?? null, Auth::guard('admin')->id());

        $this->audit->log('admin.invite.created', 'admin', Auth::guard('admin')->id(), 'invite', $invite->id, [
            'note' => $invite->note,
            'expires_at' => $invite->expires_at->toIso8601String(),
        ], $request);

        return redirect()->route('admin.invites.index')
            ->with('status', 'Invite created.')
            ->with('invite_url', $this->invites->url($plain));
    }

    public function destroy(Request $request, RegistrationInvite $invite): RedirectResponse
    {
        if ($invite->used_at === null) {
            $invite->forceFill(['revoked_at' => now()])->save();

            $this->audit->log('admin.invite.revoked', 'admin', Auth::guard('admin')->id(), 'invite', $invite->id, [], $request);
        }

        return redirect()->route('admin.invites.index')->with('status', 'Invite revoked.');
    }
}
