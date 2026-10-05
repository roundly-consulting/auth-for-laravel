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
 * The package's rate limiting, on Laravel's RateLimiter. Attempts are taken BEFORE any
 * credential work (so bcrypt cost is never spent on a throttled request, and a burst of
 * concurrent guesses cannot all pass a check that none of them has been counted in yet).
 */
final readonly class Throttle
{
    public function __construct(
        private RateLimiter $limiter,
        private ThrottleKey $keys,
        private RecordLoginActivity $recordActivity,
    ) {}

    /**
     * Take one attempt from every bucket BEFORE any credential work — an atomic
     * `increment`, never a read-then-write, so N concurrent requests are N attempts
     * even while none of them has finished hashing. A request over any limit gives its
     * attempts back and is refused with {@see TooManyAttempts}: recorded as `Throttled`
     * under `$recordAs`, with {@see LoginThrottled} dispatched.
     *
     * Volumetric buckets keep the attempt; where only failures count, the caller
     * {@see self::release()}s it once the credential proved valid.
     *
     * @param  list<ThrottleKind>  $kinds
     *
     * @throws TooManyAttempts
     */
    public function attempt(
        GuardConfig $guard,
        array $kinds,
        #[SensitiveParameter] ?string $identifier,
        SessionContext $context,
        ?ActivityType $recordAs = null,
    ): void {
        $taken = [];

        foreach ($kinds as $kind) {
            $key = $this->keys->for($guard, $kind, $identifier, $context->ipAddress);
            $limit = $guard->throttle($kind);
            $taken[$key] = $limit->decaySeconds;

            if ($this->limiter->increment($key, $limit->decaySeconds) <= $limit->maxAttempts) {
                continue;
            }

            foreach ($taken as $takenKey => $decay) {
                $this->limiter->decrement($takenKey, $decay);
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
     * Give back the attempt {@see self::attempt()} took, for buckets that count failures
     * only — the credential turned out valid, or the request failed for a reason that
     * is not a guess.
     *
     * @param  list<ThrottleKind>  $kinds
     */
    public function release(GuardConfig $guard, array $kinds, #[SensitiveParameter] ?string $identifier, ?string $ip): void
    {
        foreach ($kinds as $kind) {
            $key = $this->keys->for($guard, $kind, $identifier, $ip);

            // A bucket that expired meanwhile has nothing to give back (never go negative).
            if ($this->limiter->attempts($key) > 0) {
                $this->limiter->decrement($key, $guard->throttle($kind)->decaySeconds);
            }
        }
    }

    public function clear(GuardConfig $guard, ThrottleKind $kind, #[SensitiveParameter] ?string $identifier, ?string $ip): void
    {
        $this->limiter->clear($this->keys->for($guard, $kind, $identifier, $ip));
    }

    /**
     * A per-account cooldown: true (and started) when the key is free, false while it runs.
     * One atomic `increment`, never a check-then-hit — of N concurrent callers exactly one
     * sees the first hit. The window is fixed: hits inside it do not extend it.
     */
    public function cooldown(string $key, int $seconds): bool
    {
        if ($seconds <= 0) {
            return true;
        }

        return $this->limiter->increment($key, $seconds) === 1;
    }

}
