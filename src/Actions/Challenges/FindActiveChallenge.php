<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Exceptions\ChallengeInvalid;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Support\ChallengeFingerprint;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use SensitiveParameter;

/**
 * Loads an active challenge by `(guard, HMAC(token))`. Unknown, expired, completed,
 * invalidated and foreign-guard tokens are one uniform {@see ChallengeInvalid}; a
 * fingerprint mismatch counts as a failed attempt first.
 *
 * @internal a challenge-engine step; drive challenges through `challenges()`.
 */
final readonly class FindActiveChallenge
{
    public function __construct(
        private GuardRegistry $guards,
        private SecretHasher $hasher,
        private ChallengeFingerprint $fingerprint,
        private RecordChallengeFailure $recordFailure,
    ) {}

    /**
     * @throws ChallengeInvalid
     */
    public function execute(string $guard, #[SensitiveParameter] string $token, SessionContext $context): LoginChallenge
    {
        $config = $this->guards->get($guard);

        $challenge = Models::challenges()
            ->forGuard($config->name())
            ->where('token_hash', $this->hasher->link($config->name(), 'challenge', $token))
            ->active(CarbonImmutable::now())
            ->first();

        if ($challenge === null) {
            throw new ChallengeInvalid;
        }

        $expected = $challenge->fingerprint_hash;
        $actual = $this->fingerprint->for($config, $context);

        if ($expected !== null && ($actual === null || ! ConstantTime::equals($expected, $actual))) {
            $this->recordFailure->execute($challenge, ActivityOutcome::FingerprintMismatch, $context);

            throw new ChallengeInvalid;
        }

        return $challenge;
    }
}
