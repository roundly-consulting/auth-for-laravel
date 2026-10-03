<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationProof;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;

/**
 * The "recently re-authenticated" marker of one session (`sid`), kept in the
 * `authentication.reauthentication_store` cache store. It records the method as well as
 * the time, so the check can require a second-factor proof from an account that has
 * (or has since enrolled) one.
 */
final readonly class ReauthenticationMarker
{
    public function __construct(private CacheFactory $cache) {}

    public function put(string $guard, string $sessionKey, ReauthenticationProof $proof, int $ttl): void
    {
        $this->store()->put($this->key($guard, $sessionKey), ['method' => $proof->method->value, 'at' => $proof->at->getTimestamp()], $ttl);
    }

    /**
     * The session's last proof, or null — also for a marker that does not name its method.
     */
    public function proof(string $guard, string $sessionKey): ?ReauthenticationProof
    {
        $stored = $this->store()->get($this->key($guard, $sessionKey));
        $method = is_array($stored) && is_string($stored['method'] ?? null) ? ReauthenticationMethod::tryFrom($stored['method']) : null;

        return $method !== null && is_int($stored['at'] ?? null)
            ? new ReauthenticationProof($method, CarbonImmutable::createFromTimestamp($stored['at']))
            : null;
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

        // Null or blank (an empty env var) is the default store; anything but a string throws.
        if ($store !== null && ! is_string($store)) {
            throw AuthenticationMisconfigured::because('authentication.reauthentication_store must be a cache store name or null.');
        }

        return $this->cache->store($store === null || trim($store) === '' ? null : $store);
    }
}
