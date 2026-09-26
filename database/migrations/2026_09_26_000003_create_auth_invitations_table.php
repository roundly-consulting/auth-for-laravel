<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Auth\Support\Tables;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * Invitations. No foreign keys: the inviter and the created account are polymorphic
 * (the inviter may even belong to another guard). "One pending invitation per
 * (guard, email)" is enforced in CreateInvitation, not by a partial unique index
 * (pgsql-only syntax).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(Tables::invitations(), function (Blueprint $table): void {
            $keyType = KeyType::fromConfig('authentication.key_type');

            $table->id();
            $table->string('guard', 64);
            $table->string('email', 255)->index();
            $table->char('token_hash', 64)->nullable()->unique();
            $table->morphKey('inviter', $keyType, nullable: true);
            $table->morphKey('account', $keyType, nullable: true);
            $table->jsonb('payload')->nullable();
            $table->string('locale', 12)->nullable();
            $table->unsignedSmallInteger('send_count')->default(0);
            $table->timestamp('last_sent_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('accepted_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->index(['guard', 'email']);
        });
    }
};
