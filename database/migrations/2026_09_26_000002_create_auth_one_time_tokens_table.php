<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\Support\Tables;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * Emailed single-use secrets, stored as keyed HMACs only. No foreign keys: the account
 * is polymorphic.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(Tables::oneTimeTokens(), function (Blueprint $table): void {
            $table->id();
            $table->string('guard', 64);
            $table->string('purpose', 32);
            $table->morphKey('account', KeyType::fromConfig('authentication.key_type'), nullable: false);
            $table->string('email', 255);
            $table->char('token_hash', 64)->nullable()->unique();
            // Not unique: codes repeat across accounts; the MAC input binds the email.
            $table->char('code_hash', 64)->nullable();
            $table->char('fingerprint_hash', 64)->nullable();
            $table->unsignedSmallInteger('attempts')->default(0);
            $table->unsignedSmallInteger('max_attempts')->default(1);
            $table->jsonb('payload')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamp('consumed_at')->nullable();
            $table->timestamp('invalidated_at')->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->index(['guard', 'purpose', 'email']);
            $table->index(['account_type', 'account_id', 'purpose']);
        });
    }
};
