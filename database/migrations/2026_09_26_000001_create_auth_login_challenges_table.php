<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\Support\Tables;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * Pending multi-step logins. No foreign keys: the account is polymorphic (one table per
 * guard), so it cannot be constrained.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(Tables::challenges(), function (Blueprint $table): void {
            $table->id();
            $table->string('guard', 64);
            $table->morphKey('account', KeyType::fromConfig('authentication.key_type'), nullable: false);
            $table->char('token_hash', 64)->unique();
            $table->string('method', 32);
            $table->jsonb('required_steps');
            $table->jsonb('completed_steps');
            $table->jsonb('context')->nullable();
            $table->char('fingerprint_hash', 64)->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->unsignedSmallInteger('attempts')->default(0);
            $table->unsignedSmallInteger('max_attempts');
            $table->unsignedInteger('version')->default(0);
            $table->timestamp('expires_at')->index();
            $table->timestamp('completed_at')->nullable();
            $table->timestamp('invalidated_at')->nullable();
            $table->string('invalidated_reason', 32)->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->index(['guard', 'account_type', 'account_id']);
        });
    }
};
