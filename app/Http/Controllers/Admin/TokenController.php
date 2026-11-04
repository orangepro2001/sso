<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AccessToken;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

/**
 * Token inventory: what is live right now, and a kill switch per token.
 */
class TokenController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function index(Request $request): View
    {
        $subject = (string) $request->query('subject', 'all');

        $tokens = AccessToken::query()
            ->with(['user', 'guestDevice'])
            ->when($subject !== 'all', fn ($q) => $q->where('subject_type', $subject))
            ->latest('id')
            ->paginate(50)
            ->withQueryString();

        return view('admin.tokens.index', ['tokens' => $tokens, 'subject' => $subject]);
    }

    public function revoke(Request $request, AccessToken $token): RedirectResponse
    {
        if ($token->revoked_at === null) {
            $token->forceFill(['revoked_at' => now()])->save();
            $this->audit->log('admin.token.revoked', 'admin', Auth::guard('admin')->id(), 'token', $token->jti, [], $request);
        }

        return redirect()->back()->with('status', 'Token revoked.');
    }
}
