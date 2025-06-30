<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;

class UserSeeder extends Seeder
{
    public function run()
    {
        $adminRole = Role::firstOrCreate(['name' => 'admin']);
        $dosenRole = Role::firstOrCreate(['name' => 'dosen']);
        $mahasiswaRole = Role::firstOrCreate(['name' => 'mahasiswa']);

        $admin = User::create([
            'name' => 'Admin User',
            'username' => 'admin',
            'email' => 'admin@example.com',
            'password' => bcrypt('admin123'),
            'security_hint' => bcrypt('adminhint'),
        ]);
        $admin->assignRole($adminRole);

        $dosen = User::create([
            'name' => 'Dosen Example',
            'nip' => '123456',
            'password' => bcrypt('dosen123'),
            'security_hint' => bcrypt('dosenhint'),
        ]);
        $dosen->assignRole($dosenRole);

        $mahasiswa = User::create([
            'name' => 'Mahasiswa Example',
            'nim' => '20210001',
            'password' => bcrypt('mahasiswa123'),
            'security_hint' => bcrypt('mahasiswahint'),
        ]);
        $mahasiswa->assignRole($mahasiswaRole);
    }
}