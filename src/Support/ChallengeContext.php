<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Models\LoginChallenge;

/**
 * Writes one value into a pending challenge's context with the same optimistic
 * `version` check every step uses — e.g. the passkey ceremony a step started, which the
 * assertion must later match.
 */
final class ChallengeContext
{
    public static function put(LoginChallenge $challenge, string $key, mixed $value): void
    {
        $context = $challenge->context ?? [];
        $context[$key] = $value;

        $written = Models::challenges()
            ->whereKey($challenge->getKey())
            ->where('version', $challenge->version)
            ->active(CarbonImmutable::now())
            ->update(['context' => json_encode($context, JSON_THROW_ON_ERROR), 'version' => $challenge->version + 1]);

        if ($written === 0) {
            throw new ChallengeInvalid;
        }
    }
}
