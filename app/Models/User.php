<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable, HasRoles;

    protected $fillable = [
        'name',
        'email',
        'username',
        'nip',
        'nim',
        'password',
        'security_hint',
        'banned_until',
        'login_attempts',
        'is_login'
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'banned_until' => 'datetime',
    ];

    public function isBanned()
    {
        return $this->banned_until && now()->lessThan($this->banned_until);
    }

    public function banDuration()
    {
        if (!$this->banned_until) return 0;
        return now()->diffInSeconds($this->banned_until);
    }
}