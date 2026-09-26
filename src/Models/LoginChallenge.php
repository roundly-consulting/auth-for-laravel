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
use RoundlyConsulting\Auth\Database\Factories\LoginChallengeFactory;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Support\Tables;

/**
 * A pending multi-step login. Only the HMAC of its token is stored. Progress is written
 * with optimistic `version` checks and every claim is a conditional update — never a
 * read-then-save.
 *
 * Not final: `authentication.models.challenge` may point at a subclass.
 *
 * @property int $id
 * @property string $guard
 * @property string $account_type
 * @property int|string $account_id
 * @property string $token_hash
 * @property LoginMethod $method
 * @property array<int, mixed> $required_steps
 * @property array<int, mixed> $completed_steps
 * @property array<string, mixed>|null $context
 * @property string|null $fingerprint_hash
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property int $attempts
 * @property int $max_attempts
 * @property int $version
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $completed_at
 * @property CarbonImmutable|null $invalidated_at
 * @property string|null $invalidated_reason
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 * @property CarbonInterface|null $deleted_at
 * @property-read Model|null $account
 */
class LoginChallenge extends Model
{
    /** @use HasFactory<LoginChallengeFactory> */
    use HasFactory;

    use Prunable;
    use SoftDeletes;

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['token_hash', 'fingerprint_hash'];

    /** @var array<string, mixed> */
    protected $attributes = ['attempts' => 0, 'version' => 0];

    public function getTable(): string
    {
        return Tables::challenges();
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function account(): MorphTo
    {
        return $this->morphTo('account');
    }

    /**
     * Not completed, not invalidated and not expired at `$now` (expiry is exclusive:
     * exactly-at-expiry is expired).
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeActive(Builder $query, ?CarbonImmutable $now = null): Builder
    {
        return $query->whereNull('completed_at')
            ->whereNull('invalidated_at')
            ->where('expires_at', '>', $now ?? CarbonImmutable::now());
    }

    /**
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeForGuard(Builder $query, string $guard): Builder
    {
        return $query->where('guard', $guard);
    }

    /**
     * @return list<ChallengeRequirement>
     */
    public function remaining(): array
    {
        $requirements = [];

        foreach ($this->required_steps as $stored) {
            $requirement = ChallengeRequirement::fromStorage($stored);

            if ($requirement !== null) {
                $requirements[] = $requirement;
            }
        }

        return $requirements;
    }

    /**
     * @return list<ChallengeStep>
     */
    public function completed(): array
    {
        $steps = [];

        foreach ($this->completed_steps as $value) {
            $step = is_string($value) ? ChallengeStep::tryFrom($value) : null;

            if ($step !== null) {
                $steps[] = $step;
            }
        }

        return $steps;
    }

    /**
     * @return list<AuthMethodReference>
     */
    public function authMethods(): array
    {
        return AuthMethodReference::fromValues($this->context['amr'] ?? null);
    }

    public function contextValue(string $key): mixed
    {
        return $this->context[$key] ?? null;
    }

    public function attemptsLeft(): int
    {
        return max(0, $this->max_attempts - $this->attempts);
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
            'method' => LoginMethod::class,
            'required_steps' => 'array',
            'completed_steps' => 'array',
            'context' => 'array',
            'attempts' => 'integer',
            'max_attempts' => 'integer',
            'version' => 'integer',
            'expires_at' => 'immutable_datetime',
            'completed_at' => 'immutable_datetime',
            'invalidated_at' => 'immutable_datetime',
        ];
    }

    protected static function newFactory(): LoginChallengeFactory
    {
        return LoginChallengeFactory::new();
    }
}
