<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\Support\Tables;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * One row per authentication attempt. No foreign keys: the account is polymorphic and
 * nullable (unidentified attempts), and `challenge_id` points at a row that is pruned
 * first.
 */
return new class extends Migration
{
    /**
     * Composite indexes carry explicit short names: MySQL caps identifiers at 64
     * characters, and Postgres index names are schema-wide.
     */
    public function up(): void
    {
        Schema::create(Tables::loginActivities(), function (Blueprint $table): void {
            $table->id();
            $table->string('guard', 64);
            $table->morphKey('account', KeyType::fromConfig('authentication.key_type'), nullable: true);
            $table->string('type', 32);
            $table->string('outcome', 32);
            $table->string('method', 32)->nullable();
            $table->string('reason', 64)->nullable();
            $table->string('identifier', 255)->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->char('device_fingerprint', 64)->nullable();
            $table->uuid('session_id')->nullable();
            $table->unsignedBigInteger('challenge_id')->nullable();
            $table->boolean('is_new_device')->default(false);
            $table->char('country_code', 2)->nullable();
            $table->string('city', 255)->nullable();
            $table->jsonb('meta')->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->index(['account_type', 'account_id', 'created_at'], 'auth_activity_account_created_index');
            $table->index(['account_type', 'account_id', 'device_fingerprint', 'outcome'], 'auth_activity_account_device_index');
            $table->index(['guard', 'created_at'], 'auth_activity_guard_created_index');
            $table->index(['ip_address', 'created_at'], 'auth_activity_ip_created_index');
        });
    }
};
