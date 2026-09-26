<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use Illuminate\Contracts\Cache\Repository as Cache;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Facades\Passkeys;

/**
 * Options for a passwordless (discoverable, usernameless) passkey login. No identifier
 * is accepted, so the options never reveal whether an account exists. With
 * `passkeys.satisfies_mfa` the ceremony REQUIRES user verification — enforced by the
 * verifier for this ceremony whatever the global passkeys setting says — so `mfa` in
 * `amr` is a proven fact. The ceremony is remembered for this guard's login endpoint.
 * Throttled per IP: every call writes a ceremony into the cache.
 */
final readonly class BeginPasskeyLogin
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private Cache $cache,
    ) {}

    public function execute(string $guard, SessionContext $context): RequestOptionsData
    {
        $config = $this->guards->get($guard);

        if (! $config->loginMethodEnabled(LoginMethod::Passkey)) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->attempt($config, [ThrottleKind::LoginIp], null, $context, ActivityType::PasskeyLogin);

        $requireUv = $config->passkeySatisfiesMfa();

        $options = Passkeys::authenticationOptions(null, $requireUv ? new AuthenticationOptionsOverrides(userVerification: UserVerification::Required) : null);

        $this->cache->put(self::key($guard, $options->ceremonyId), $requireUv ? 'uv' : 'up', $config->challengeTtl());

        return $options;
    }

    /**
     * @internal the cache key binding a ceremony to a guard's passwordless login
     */
    public static function key(string $guard, string $ceremonyId): string
    {
        return "authentication:passkey-login:{$guard}:{$ceremonyId}";
    }
}
