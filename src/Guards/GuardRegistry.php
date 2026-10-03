<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Exceptions\GuardNotConfigured;
use RoundlyConsulting\Auth\Support\ConfigValidation;

/**
 * Resolves (and validates) the per-guard configuration. Memoised per name for the life
 * of the container instance — it is bound `scoped()`, so Octane / queue workers get a
 * fresh registry per request/job; call {@see self::flush()} after changing config at
 * runtime (tests).
 */
final class GuardRegistry
{
    /** @var array<string, GuardConfig> */
    private array $resolved = [];

    /** @var array<string, GuardConfig>|null */
    private ?array $unvalidated = null;

    /**
     * The validated configuration of a guard (null → `authentication.default`).
     *
     * @throws GuardNotConfigured
     */
    public function get(?string $name = null): GuardConfig
    {
        $name ??= $this->defaultGuard();

        if (isset($this->resolved[$name])) {
            return $this->resolved[$name];
        }

        $guard = $this->all()[$name] ?? throw GuardNotConfigured::named($name);

        ConfigValidation::assertValid($guard, $this);

        return $this->resolved[$name] = $guard;
    }

    /**
     * The validated configuration of a guard, once the account is proven to be one of
     * the guard's model — every action taking an account resolves its guard through
     * here, so a foreign account is refused before anything is written.
     *
     * @throws GuardNotConfigured
     * @throws AuthenticationMisconfigured when the account belongs to another guard
     */
    public function owning(?string $name, Account $account): GuardConfig
    {
        $guard = $this->get($name);

        (new AccountRepository($guard))->ensureOwns($account);

        return $guard;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->all());
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->all());
    }

    public function defaultGuard(): string
    {
        $default = config('authentication.default');

        // Not set (absent, null or blank — an empty AUTHENTICATION_GUARD=) is the shipped guard.
        if ($default === null || (is_string($default) && trim($default) === '')) {
            return 'users';
        }

        if (! is_string($default)) {
            throw AuthenticationMisconfigured::because('authentication.default must be a guard name.');
        }

        return $default;
    }

    /**
     * Every configured guard, built but NOT validated (validation needs this list).
     *
     * @return array<string, GuardConfig>
     */
    public function all(): array
    {
        if ($this->unvalidated !== null) {
            return $this->unvalidated;
        }

        $defaults = config('authentication.defaults') ?? [];
        $guards = config('authentication.guards') ?? [];
        $built = [];

        // A mistyped section must not silently become "no defaults" or "no guards".
        if (! is_array($defaults)) {
            throw AuthenticationMisconfigured::because('authentication.defaults must be an array.');
        }

        if (! is_array($guards)) {
            throw AuthenticationMisconfigured::because('authentication.guards must be an array keyed by guard name.');
        }

        foreach ($guards as $name => $settings) {
            if (! is_string($name) || $name === '') {
                throw AuthenticationMisconfigured::because('authentication.guards must be keyed by guard name.');
            }

            if (! is_array($settings)) {
                throw AuthenticationMisconfigured::because("authentication.guards.{$name} must be an array.");
            }

            /** @var array<string, mixed> $merged */
            $merged = ConfigMerger::merge($defaults, $settings);

            $built[$name] = new GuardConfig($name, $merged);
        }

        return $this->unvalidated = $built;
    }

    /**
     * The guard whose model has this morph class — the reverse map for listeners that
     * only receive an owner type (e.g. refresh-token reuse detection).
     */
    public function forMorphClass(string $morphClass): ?GuardConfig
    {
        foreach ($this->all() as $name => $guard) {
            $model = $guard->configuredModel();

            if ($model !== null && is_subclass_of($model, Model::class) && (new $model)->getMorphClass() === $morphClass) {
                return $this->get($name);
            }
        }

        return null;
    }

    public function forModel(Model $model): ?GuardConfig
    {
        return $this->forMorphClass($model->getMorphClass());
    }

    public function flush(): void
    {
        $this->resolved = [];
        $this->unvalidated = null;
    }
}
