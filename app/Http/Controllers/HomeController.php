<?php

namespace App\Http\Controllers;

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
        return view('home', [
            'user' => $request->user('web'),
            'pending' => $request->session()->get('oauth.pending'),
        ]);
    }
}
