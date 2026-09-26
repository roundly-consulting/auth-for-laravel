<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository;

/**
 * The "recently re-authenticated" marker of one session (`sid`), kept in the
 * `authentication.reauthentication_store` cache store.
 */
final readonly class ReauthenticationMarker
{
    public function __construct(private CacheFactory $cache) {}

    public function put(string $guard, string $sessionKey, CarbonImmutable $at, int $ttl): void
    {
        $this->store()->put($this->key($guard, $sessionKey), $at->getTimestamp(), $ttl);
    }

    public function at(string $guard, string $sessionKey): ?CarbonImmutable
    {
        $timestamp = $this->store()->get($this->key($guard, $sessionKey));

        return is_int($timestamp) ? CarbonImmutable::createFromTimestamp($timestamp) : null;
    }

    public function forget(string $guard, string $sessionKey): void
    {
        $this->store()->forget($this->key($guard, $sessionKey));
    }

    /**
     * A ceremony id bound to this session (re-authentication passkey options).
     */
    public function bindCeremony(string $guard, string $sessionKey, string $ceremonyId, int $ttl): void
    {
        $this->store()->put($this->key($guard, $sessionKey).':ceremony', $ceremonyId, $ttl);
    }

    public function pullCeremony(string $guard, string $sessionKey): ?string
    {
        $ceremony = $this->store()->pull($this->key($guard, $sessionKey).':ceremony');

        return is_string($ceremony) ? $ceremony : null;
    }

    private function key(string $guard, string $sessionKey): string
    {
        return "authentication:reauth:{$guard}:{$sessionKey}";
    }

    private function store(): Repository
    {
        $store = config('authentication.reauthentication_store');

        return $this->cache->store(is_string($store) && $store !== '' ? $store : null);
    }
}
