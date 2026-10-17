<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Static-analysis fixture (never executed): a host migration calling the schema macro the way the
 * published users-table stub and `authentication:guard` migrations do, analysed by
 * `composer analyse` so the macro stays visible to Larastan without a booted provider.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->authenticationColumns();
        });

        Schema::create('clients', function (Blueprint $table): void {
            $table->id();
            $table->string('email')->unique();
            $table->authenticationColumns();
            $table->timestamps();
        });
    }
};
