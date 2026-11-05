<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Serves profile pictures.
 *
 * Anonymous by design, with an HMAC signature in the URL: another application reads
 * this URL server-side from the `picture` claim and has no session to offer. The
 * signature covers the user id and the version, so it is unguessable, it changes when
 * the picture changes, and it can be cached forever.
 */
class AvatarController extends Controller
{
    public function __invoke(Request $request, User $user, string $v): StreamedResponse
    {
        $signature = (string) $request->query('sig', '');
        $expected = hash_hmac('sha256', $user->id.'|'.$v, (string) config('app.key'));

        abort_unless(hash_equals($expected, $signature), 403);
        abort_if($user->avatar_path === null || ! Storage::disk('local')->exists($user->avatar_path), 404);

        return Storage::disk('local')->response($user->avatar_path, null, [
            'Content-Type' => $user->avatar_mime ?: 'application/octet-stream',
            'Cache-Control' => 'public, max-age=31536000, immutable',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
