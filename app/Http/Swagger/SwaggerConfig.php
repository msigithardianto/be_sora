<?php

namespace App\Http\Swagger;

/**
 * @OA\OpenApi(
 *     @OA\Info(
 *         version="1.0.0",
 *         title="Laravel Auth API",
 *         description="API documentation for Authentication System with role-based login",
 *         @OA\Contact(email="support@example.com")
 *     ),
 *     @OA\Server(url=L5_SWAGGER_CONST_HOST),
 *     @OA\Components(
 *         @OA\SecurityScheme(
 *             securityScheme="sanctum",
 *             type="http",
 *             scheme="bearer",
 *             bearerFormat="JWT"
 *         ),
 *         @OA\Schema(
 *             schema="User",
 *             type="object",
 *             @OA\Property(property="id", type="integer"),
 *             @OA\Property(property="name", type="string"),
 *             @OA\Property(property="email", type="string"),
 *             @OA\Property(property="username", type="string"),
 *             @OA\Property(property="nip", type="string"),
 *             @OA\Property(property="nim", type="string"),
 *             @OA\Property(property="created_at", type="string", format="date-time"),
 *             @OA\Property(property="updated_at", type="string", format="date-time"),
 *             @OA\Property(
 *                 property="roles",
 *                 type="array",
 *                 @OA\Items(
 *                     type="object",
 *                     @OA\Property(property="name", type="string", example="admin|dosen|mahasiswa")
 *                 )
 *             )
 *         ),
 *         @OA\Schema(
 *             schema="TokenResponse",
 *             type="object",
 *             @OA\Property(property="token", type="string"),
 *             @OA\Property(property="token_type", type="string", example="Bearer"),
 *             @OA\Property(
 *                 property="user",
 *                 ref="#/components/schemas/User"
 *             ),
 *             @OA\Property(
 *                 property="active_sessions",
 *                 type="array",
 *                 @OA\Items(
 *                     type="object",
 *                     @OA\Property(property="id", type="integer"),
 *                     @OA\Property(property="device", type="string"),
 *                     @OA\Property(property="last_active", type="string", format="date-time"),
 *                     @OA\Property(property="current", type="boolean")
 *                 )
 *             )
 *         )
 *     )
 * )
 */
class SwaggerConfig
{
    // Class for Swagger annotations only
}