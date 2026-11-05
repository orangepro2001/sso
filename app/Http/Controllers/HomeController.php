<?php

namespace App\Http\Controllers;

use App\Models\OauthClient;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;

/**
 * The public front door.
 *
 * It used to be a status board: signing-key count, guest-channel state, and the
 * whole endpoint table — internal operational detail, rendered to anyone on the
 * internet, and useful to nobody standing there. What a visitor needs is one thing:
 * the way in. The endpoint list now lives in the console, where the person who needs
 * it is already signed in (admin/dashboard.blade.php).
 */
class HomeController extends Controller
{
    public function __invoke(Request $request): View
    {
        $user = $request->user('web');

        return view('home', [
            'user' => $user,
            'pending' => $request->session()->get('oauth.pending'),
            // The launcher: applications an administrator pointed at a page a person
            // can open. A client registered only for machine use stays invisible.
            'apps' => $user === null ? collect() : OauthClient::query()
                ->where('active', true)
                ->where('in_launcher', true)
                ->whereNotNull('home_url')
                ->orderBy('sort_order')
                ->orderBy('name')
                ->get(['id', 'client_id', 'name', 'home_url', 'note']),
        ]);
    }
}
