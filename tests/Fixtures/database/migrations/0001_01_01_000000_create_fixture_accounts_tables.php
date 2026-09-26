<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        foreach (['users', 'clients'] as $name) {
            Schema::create($name, function (Blueprint $table): void {
                $table->id();
                $table->string('name')->nullable();
                $table->string('email')->unique();
                $table->timestamp('email_verified_at')->nullable();
                $table->string('password')->nullable();
                $table->authenticationColumns();
                $table->twoFactorColumns();
                $table->passkeyUserHandle();
                $table->timestamps();
                $table->softDeletes();
            });
        }
    }
};
