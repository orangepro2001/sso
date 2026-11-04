<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;

/**
 * Liveness/readiness probe. Deliberately does not touch the database so that the
 * container reports healthy even while PostgreSQL is briefly unreachable; the
 * service answers, and that is what a restart loop should be keyed on.
 */
class HealthController extends Controller
{
    public function __invoke(): JsonResponse
    {
        return response()->json([
            'status' => 'ok',
            'service' => 'sso',
            'issuer' => config('sso.issuer'),
            'time' => now()->toIso8601String(),
        ]);
    }
}
