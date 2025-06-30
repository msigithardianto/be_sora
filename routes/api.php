<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

Route::prefix('auth')->group(function () {

    Route::post('/login', [AuthController::class, 'login']);

    Route::middleware(['auth:sanctum', 'check.force.logout'])->group(function () {
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::post('/logout-all', [AuthController::class, 'logoutAll']);
        Route::post('/validate-hint', [AuthController::class, 'validateHint']);
        Route::get('/user', [AuthController::class, 'getUser']);
        Route::get('/active-sessions', [AuthController::class, 'getActiveSessions']);    
        Route::post('/refresh', [AuthController::class, 'refreshToken']);
    });
});
