<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\DB;

/**
 * @OA\Tag(
 *     name="Authentication",
 *     description="API Endpoints for Authentication"
 * )
 */
class AuthController extends Controller
{
    /**
     * @OA\Post(
     *     path="/api/auth/login",
     *     tags={"Authentication"},
     *     summary="Login user",
     *     operationId="login",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"identifier","password","role"},
     *             @OA\Property(property="identifier", type="string", example="admin@example.com|1234567890123456|20210001"),
     *             @OA\Property(property="password", type="string", example="password123"),
     *             @OA\Property(property="role", type="string", enum={"admin","dosen","mahasiswa"}, example="admin")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Successful login",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string"),
     *             @OA\Property(property="refresh_token", type="string"),
     *             @OA\Property(property="token_type", type="string", example="Bearer"),
     *             @OA\Property(property="user", ref="#/components/schemas/User"),
     *             @OA\Property(property="expires_in", type="integer", example=3600)
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Validation error"
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Account banned or already logged in"
     *     )
     * )
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'identifier' => 'required|string',
            'password' => 'required|string',
            'role' => 'required|string|in:admin,dosen,mahasiswa'
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()->first()], 400);
        }

        $user = $this->findUserByIdentifier($request->identifier, $request->role);

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        if ($user->is_login && !$user->hasRole('admin')) {
            return response()->json([
                'message' => 'User is already logged in from another device',
                'error_code' => 'already_logged_in'
            ], 403);
        }

        if (!$this->validateIdentifierForRole($user, $request->identifier, $request->role)) {
            return response()->json(['message' => 'Invalid login method for your role'], 401);
        }

        if ($user->isBanned()) {
            return response()->json([
                'message' => 'You are banned for ' . $user->banDuration() . ' seconds',
                'remaining_time' => $user->banDuration(),
                'error_code' => 'banned'
            ], 403);
        }

        if (!Auth::attempt($this->getCredentials($user, $request->identifier, $request->password))) {
            $user->increment('login_attempts');

            $banDuration = $this->calculateBanDuration($user->login_attempts);
            if ($banDuration > 0) {
                $user->update(['banned_until' => now()->addSeconds($banDuration)]);
                return response()->json([
                    'message' => 'You are banned for ' . $banDuration . ' seconds',
                    'remaining_time' => $banDuration
                ], 403);
            }

            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        // Reset login info
        $user->update([
            'login_attempts' => 0,
            'banned_until' => null,
            'is_login' => true,
            'last_login_at' => now()
        ]);

        $accessExpiration = (int) config('sanctum.expiration', 60);
        $refreshExpiration = (int) config('sanctum.rt_expiration', 10080);

        if ($accessExpiration <= 0) $accessExpiration = 60;
        if ($refreshExpiration <= 0) $refreshExpiration = 10080;

        $accessToken = $user->createToken(
            'access_token',
            ['*'],
            now()->addMinutes($accessExpiration)
        )->plainTextToken;

        $refreshToken = $user->createToken(
            'refresh_token',
            ['refresh'],
            now()->addMinutes($refreshExpiration)
        )->plainTextToken;

        return response()->json([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'token_type' => 'Bearer',
            'user' => $user->load('roles'),
            'expires_in' => $accessExpiration * 60, 
            'active_sessions' => $this->getActiveSessionsForUser($user),
        ]);
    }


    /**
     * @OA\Post(
     *     path="/api/auth/refresh",
     *     tags={"Authentication"},
     *     summary="Refresh access token",
     *     operationId="refreshToken",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"refresh_token"},
     *             @OA\Property(property="refresh_token", type="string")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Token refreshed",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string"),
     *             @OA\Property(property="refresh_token", type="string"),
     *             @OA\Property(property="token_type", type="string", example="Bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=3600)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     )
     * )
     */
    public function refreshToken(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => $validator->errors()->first()
            ], 422);
        }

        $refreshToken = PersonalAccessToken::findToken($request->refresh_token);

        if (
            !$refreshToken ||
            !$refreshToken->can('refresh') ||
            $refreshToken->expires_at && now()->greaterThan($refreshToken->expires_at)
        ) {
            return response()->json([
                'message' => 'Invalid or expired refresh token'
            ], 401);
        }

        $user = $refreshToken->tokenable;

        $user->tokens()->where('name', 'access_token')->delete();

        $accessExpiration = (int) config('sanctum.expiration', 60); // default 60 menit
        $refreshExpiration = (int) config('sanctum.rt_expiration', 10080); // default 7 hari

        $newAccessToken = $user->createToken(
            'access_token',
            ['*'],
            now()->addMinutes($accessExpiration)
        )->plainTextToken;

        $newRefreshToken = $user->createToken(
            'refresh_token',
            ['refresh'],
            now()->addMinutes($refreshExpiration)
        )->plainTextToken;

        $refreshToken->delete();

        return response()->json([
            'access_token' => $newAccessToken,
            'refresh_token' => $newRefreshToken,
            'token_type' => 'Bearer',
            'expires_in' => $accessExpiration * 60 
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/logout",
     *     tags={"Authentication"},
     *     summary="Logout user",
     *     operationId="logout",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully logged out")
     *         )
     *     )
     * )
     */
    public function logout(Request $request)
    {
        $user = $request->user();
        $user->update(['is_login' => false]);
        
        $request->user()->currentAccessToken()->delete();
        
        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * @OA\Post(
     *     path="/api/logout-all",
     *     tags={"Authentication"},
     *     summary="Logout from all devices",
     *     operationId="logoutAll",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out from all devices",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully logged out from all devices")
     *         )
     *     )
     * )
     */
    public function logoutAll(Request $request)
    {
        $user = $request->user();
        $user->update(['is_login' => false]); // Mark user as logged out
        
        $request->user()->tokens()->delete();
        
        return response()->json(['message' => 'Successfully logged out from all devices']);
    }
    /**
     * @OA\Post(
     *     path="/api/validate-hint",
     *     tags={"Authentication"},
     *     summary="Validate security hint",
     *     operationId="validateHint",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"hint"},
     *             @OA\Property(property="hint", type="string", example="mysecurityhint")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Hint validated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Hint validated successfully")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given hint is invalid")
     *         )
     *     )
     * )
     */
    public function validateHint(Request $request)
    {
        $request->validate([
            'hint' => 'required|string',
        ]);

        if (!Hash::check($request->hint, $request->user()->security_hint)) {
            return response()->json(['message' => 'The given hint is invalid'], 422);
        }

        return response()->json(['message' => 'Hint validated successfully']);
    }

    /**
     * @OA\Get(
     *     path="/api/user",
     *     tags={"Authentication"},
     *     summary="Get authenticated user",
     *     operationId="getUser",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="User data",
     *         @OA\JsonContent(ref="#/components/schemas/User")
     *     )
     * )
     */
    public function getUser(Request $request)
    {
        return response()->json($request->user()->load('roles'));
    }

    /**
     * @OA\Get(
     *     path="/api/active-sessions",
     *     tags={"Authentication"},
     *     summary="Get active sessions",
     *     operationId="getActiveSessions",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of active sessions",
     *         @OA\JsonContent(
     *             type="array",
     *             @OA\Items(
     *                 type="object",
     *                 @OA\Property(property="id", type="integer"),
     *                 @OA\Property(property="device", type="string"),
     *                 @OA\Property(property="last_active", type="string", format="date-time"),
     *                 @OA\Property(property="current", type="boolean")
     *             )
     *         )
     *     )
     * )
     */
    public function getActiveSessions(Request $request)
    {
        $user = $request->user();
        $currentToken = $request->user()->currentAccessToken();
        
        $sessions = $user->tokens()
            ->where('id', '!=', $currentToken->id)
            ->get()
            ->map(function ($token) {
                return [
                    'id' => $token->id,
                    'device' => $this->parseUserAgent($token->name),
                    'last_active' => $token->last_used_at?->toISOString(),
                    'current' => false,
                ];
            })
            ->prepend([
                'id' => $currentToken->id,
                'device' => $this->parseUserAgent($currentToken->name),
                'last_active' => now()->toISOString(),
                'current' => true,
            ]);
            
        return response()->json($sessions);
    }

    private function validateIdentifierForRole(User $user, $identifier)
    {
        if ($user->hasRole('admin')) {
            return $user->username === $identifier || $user->email === $identifier;
        }

        if ($user->hasRole('dosen')) {
            return $user->nip === $identifier;
        }

        if ($user->hasRole('mahasiswa')) {
            return $user->nim === $identifier;
        }

        return false;
    }

    private function findUserByIdentifier($identifier, $role)
    {
        $query = User::with('roles')->whereHas('roles', function($q) use ($role) {
            $q->where('name', $role);
        });

        if ($role === 'admin') {
            $query->where(function($q) use ($identifier) {
                $q->where('email', $identifier)
                  ->orWhere('username', $identifier);
            });
        } elseif ($role === 'dosen') {
            $query->where('nip', $identifier);
        } elseif ($role === 'mahasiswa') {
            $query->where('nim', $identifier);
        }

        return $query->first();
    }


    private function getCredentials($user, $identifier, $password)
    {
        if ($user->hasRole('admin')) {
            $field = filter_var($identifier, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';
            return [$field => $identifier, 'password' => $password];
        }

        if ($user->hasRole('dosen')) {
            return ['nip' => $identifier, 'password' => $password];
        }

        if ($user->hasRole('mahasiswa')) {
            return ['nim' => $identifier, 'password' => $password];
        }

        return ['username' => $identifier, 'password' => $password];
    }


    private function calculateBanDuration($attempts)
    {
        if ($attempts >= 5) return 5 * 60;
        if ($attempts >= 3) return 1 * 60;
        return 0;
    }

    private function parseUserAgent($userAgent)
    {
        if (strpos($userAgent, 'Mobile') !== false) {
            return 'Mobile Device';
        }
        if (strpos($userAgent, 'Mac') !== false) {
            return 'Mac OS';
        }
        if (strpos($userAgent, 'Windows') !== false) {
            return 'Windows';
        }
        return 'Unknown Device';
    }

    private function getActiveSessionsForUser(User $user)
    {
        return DB::table('personal_access_tokens')
            ->where('tokenable_type', User::class)
            ->where('tokenable_id', $user->id)
            ->get(['id', 'name', 'created_at']);
    }

}