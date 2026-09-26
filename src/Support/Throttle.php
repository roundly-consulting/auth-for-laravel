<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Cache\RateLimiter;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\LoginThrottled;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use SensitiveParameter;

/**
 * The package's rate limiting, on Laravel's RateLimiter. Checked BEFORE any credential
 * work (so bcrypt cost is never spent on a throttled request).
 */
final readonly class Throttle
{
    public function __construct(
        private RateLimiter $limiter,
        private ThrottleKey $keys,
        private RecordLoginActivity $recordActivity,
    ) {}

    /**
     * Throw {@see TooManyAttempts} when any bucket is exhausted — recording the attempt
     * as `Throttled` under `$recordAs` and dispatching {@see LoginThrottled}.
     *
     * @param  list<ThrottleKind>  $kinds
     */
    public function ensure(
        GuardConfig $guard,
        array $kinds,
        #[SensitiveParameter] ?string $identifier,
        SessionContext $context,
        ?ActivityType $recordAs = null,
    ): void {
        foreach ($kinds as $kind) {
            $key = $this->keys->for($guard, $kind, $identifier, $context->ipAddress);

            if (! $this->limiter->tooManyAttempts($key, $guard->throttle($kind)->maxAttempts)) {
                continue;
            }

            $retryAfter = max(1, $this->limiter->availableIn($key));

            event(new LoginThrottled($guard->name(), $kind, $retryAfter, $context));

            if ($recordAs !== null) {
                $this->recordActivity->execute(new LoginActivityData(
                    guard: $guard->name(),
                    type: $recordAs,
                    outcome: ActivityOutcome::Throttled,
                    context: $context,
                    reason: $kind->value,
                    identifier: $identifier,
                ));
            }

            throw TooManyAttempts::retryAfter($retryAfter);
        }
    }

    /**
     * Count one attempt in each bucket.
     *
     * @param  list<ThrottleKind>  $kinds
     */
    public function hit(GuardConfig $guard, array $kinds, #[SensitiveParameter] ?string $identifier, ?string $ip): void
    {
        foreach ($kinds as $kind) {
            $this->limiter->hit($this->keys->for($guard, $kind, $identifier, $ip), $guard->throttle($kind)->decaySeconds);
        }
    }

    /**
     * Check, then count — for volumetric buckets where every request counts.
     *
     * @param  list<ThrottleKind>  $kinds
     */
    public function attempt(
        GuardConfig $guard,
        array $kinds,
        #[SensitiveParameter] ?string $identifier,
        SessionContext $context,
        ?ActivityType $recordAs = null,
    ): void {
        $this->ensure($guard, $kinds, $identifier, $context, $recordAs);
        $this->hit($guard, $kinds, $identifier, $context->ipAddress);
    }

    public function clear(GuardConfig $guard, ThrottleKind $kind, #[SensitiveParameter] ?string $identifier, ?string $ip): void
    {
        $this->limiter->clear($this->keys->for($guard, $kind, $identifier, $ip));
    }

    /**
     * A per-account cooldown: true (and started) when the key is free, false while it runs.
     */
    public function cooldown(string $key, int $seconds): bool
    {
        if ($seconds <= 0) {
            return true;
        }

        if ($this->limiter->tooManyAttempts($key, 1)) {
            return false;
        }

        $this->limiter->hit($key, $seconds);

        return true;
    }
}
