<?php

namespace App\Http\Controllers;

use App\Services\SigningKeyService;
use Illuminate\Contracts\View\View;

class HomeController extends Controller
{
    public function __invoke(SigningKeyService $keys): View
    {
        return view('home', [
            'issuer' => rtrim((string) config('sso.issuer'), '/'),
            'guestEnabled' => (bool) config('sso.guest.enabled', true),
            'guestAlgo' => (string) config('sso.guest.algo', 'hmac-sha256'),
            'keyCount' => $keys->publishable()->count(),
        ]);
    }
}
