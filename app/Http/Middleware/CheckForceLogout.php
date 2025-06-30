<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class CheckForceLogout
{
    public function handle(Request $request, Closure $next)
    {
        if (Auth::check() && $request->user()->isBanned()) {
            Auth::logout();
            return response()->json([
                'message' => 'You are banned for ' . $request->user()->banDuration() . ' seconds'
            ], 403);
        }

        return $next($request);
    }
}