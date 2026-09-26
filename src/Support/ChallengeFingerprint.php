<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * Binds a pending challenge to the device that started it: HMAC over the parts the
 * guard's `challenge.bind` enables (user agent and device header by default; IP off,
 * because mobile clients hop networks mid-login). Null when nothing is bound.
 */
final readonly class ChallengeFingerprint
{
    public function __construct(private SecretHasher $hasher) {}

    public function for(GuardConfig $guard, SessionContext $context): ?string
    {
        if (! $guard->bindsChallengeToUserAgent() && ! $guard->bindsChallengeToIp() && ! $guard->bindsChallengeToDeviceHeader()) {
            return null;
        }

        return $this->hasher->fingerprint(
            $guard->name(),
            'challenge',
            $guard->bindsChallengeToUserAgent() ? $context->userAgent : null,
            $guard->bindsChallengeToIp() ? $context->ipAddress : null,
            $guard->bindsChallengeToDeviceHeader() ? $context->deviceId : null,
        );
    }
}
