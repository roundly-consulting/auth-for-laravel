<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Models;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Auth\Database\Factories\OneTimeTokenFactory;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Support\Tables;

/**
 * An emailed single-use secret (magic link, email OTP, verification, reset, email
 * change, re-authentication code), stored only as a keyed HMAC.
 *
 * Not final: `authentication.models.one_time_token` may point at a subclass.
 *
 * @property int $id
 * @property string $guard
 * @property OneTimeTokenPurpose $purpose
 * @property string $account_type
 * @property int|string $account_id
 * @property string $email
 * @property string|null $token_hash
 * @property string|null $code_hash
 * @property string|null $fingerprint_hash
 * @property int $attempts
 * @property int $max_attempts
 * @property array<string, mixed>|null $payload
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $consumed_at
 * @property CarbonImmutable|null $invalidated_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 * @property CarbonInterface|null $deleted_at
 * @property-read Model|null $account
 */
class OneTimeToken extends Model
{
    /** @use HasFactory<OneTimeTokenFactory> */
    use HasFactory;

    use Prunable;
    use SoftDeletes;

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['token_hash', 'code_hash', 'fingerprint_hash'];

    /** @var array<string, mixed> */
    protected $attributes = ['attempts' => 0, 'max_attempts' => 1];

    public function getTable(): string
    {
        return Tables::oneTimeTokens();
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function account(): MorphTo
    {
        return $this->morphTo('account');
    }

    /**
     * Not consumed, not invalidated, not expired at `$now` (exactly-at-expiry is expired).
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeUsable(Builder $query, ?CarbonImmutable $now = null): Builder
    {
        return $query->whereNull('consumed_at')
            ->whereNull('invalidated_at')
            ->where('expires_at', '>', $now ?? CarbonImmutable::now());
    }

    /**
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeForPurpose(Builder $query, string $guard, OneTimeTokenPurpose $purpose): Builder
    {
        return $query->where('guard', $guard)->where('purpose', $purpose->value);
    }

    public function payloadValue(string $key): mixed
    {
        return $this->payload[$key] ?? null;
    }

    /**
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return $this->newQuery()->where('expires_at', '<', CarbonImmutable::now()->subDay());
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'purpose' => OneTimeTokenPurpose::class,
            'payload' => 'array',
            'attempts' => 'integer',
            'max_attempts' => 'integer',
            'expires_at' => 'immutable_datetime',
            'consumed_at' => 'immutable_datetime',
            'invalidated_at' => 'immutable_datetime',
        ];
    }

    protected static function newFactory(): OneTimeTokenFactory
    {
        return OneTimeTokenFactory::new();
    }
}
