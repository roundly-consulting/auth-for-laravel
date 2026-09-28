<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\OneTimeTokens;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\FingerprintsDevices;
use RoundlyConsulting\Auth\DataTransferObjects\RedeemedSecret;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Exceptions\InvalidOneTimeToken;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use SensitiveParameter;

/**
 * Claims an emailed link exactly once (`consumed_at … WHERE consumed_at IS NULL AND
 * invalidated_at IS NULL AND expires_at > now`). The same-device binding is checked
 * BEFORE the claim, so a mismatch does not burn the user's link. After the claim the
 * link's address must still be the account's current one (except for an email change,
 * whose link targets the new address). Every failure is one uniform
 * {@see InvalidOneTimeToken}.
 *
 * @internal the one-time-token store behind links and codes.
 */
final readonly class ConsumeOneTimeToken
{
    public function __construct(
        private GuardRegistry $guards,
        private SecretHasher $hasher,
        private FingerprintsDevices $fingerprints,
    ) {}

    public function execute(string $guard, OneTimeTokenPurpose $purpose, #[SensitiveParameter] string $token, ?SessionContext $context = null): RedeemedSecret
    {
        $config = $this->guards->get($guard);
        $now = CarbonImmutable::now();

        $record = Models::oneTimeTokens()
            ->forPurpose($config->name(), $purpose)
            ->where('token_hash', $this->hasher->link($config->name(), $purpose->value, $token))
            ->usable($now)
            ->first();

        if (! $record instanceof OneTimeToken) {
            throw new InvalidOneTimeToken;
        }

        if ($record->fingerprint_hash !== null) {
            $actual = $context === null ? null : $this->fingerprints->fingerprint($context, $config);

            if ($actual === null || ! ConstantTime::equals($record->fingerprint_hash, $actual)) {
                throw new InvalidOneTimeToken;
            }
        }

        $claimed = Models::oneTimeTokens()
            ->whereKey($record->getKey())
            ->usable($now)
            ->update(['consumed_at' => $now]);

        if ($claimed === 0) {
            throw new InvalidOneTimeToken;
        }

        $accounts = new AccountRepository($config);
        $account = $accounts->findByKey($record->account_id);

        if ($account === null || $record->account_type !== $accounts->morphClass()) {
            throw new InvalidOneTimeToken;
        }

        if ($purpose !== OneTimeTokenPurpose::EmailChange
            && $accounts->normalizeEmail((string) $account->accountEmail()) !== $record->email) {
            throw new InvalidOneTimeToken;
        }

        return new RedeemedSecret($record, $account);
    }
}
