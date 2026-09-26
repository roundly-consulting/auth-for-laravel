<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\OneTimeTokens;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\DataTransferObjects\RedeemedSecret;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Exceptions\InvalidCode;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use SensitiveParameter;

/**
 * Verifies a short code against the newest usable one of `(guard, purpose, email)`:
 * an atomic bounded attempt count first (`attempts + 1 WHERE attempts < max`), then a
 * constant-time MAC comparison, then an atomic consume. With no row at all a dummy MAC
 * is still computed (timing). `attempts_left` is only revealed on authenticated paths —
 * on guest endpoints it would tell real addresses from unknown ones.
 */
final readonly class VerifyOneTimeCode
{
    public function __construct(
        private GuardRegistry $guards,
        private SecretHasher $hasher,
    ) {}

    public function execute(
        string $guard,
        OneTimeTokenPurpose $purpose,
        string $email,
        #[SensitiveParameter] string $code,
        bool $revealAttempts = false,
    ): RedeemedSecret {
        $config = $this->guards->get($guard);
        $accounts = new AccountRepository($config);
        $email = $accounts->normalizeEmail($email);
        $now = CarbonImmutable::now();
        $candidate = $this->hasher->code($config->name(), $purpose->value, $email, trim($code));

        $record = Models::oneTimeTokens()
            ->forPurpose($config->name(), $purpose)
            ->where('email', $email)
            ->whereNotNull('code_hash')
            ->usable($now)
            ->latest('id')
            ->first();

        if ($record === null) {
            throw new InvalidCode;
        }

        $counted = Models::oneTimeTokens()
            ->whereKey($record->getKey())
            ->where('attempts', '<', $record->max_attempts)
            ->usable($now)
            ->increment('attempts');

        $attemptsLeft = max(0, $record->max_attempts - $record->attempts - 1);

        if ($counted === 0 || ! ConstantTime::equals((string) $record->code_hash, $candidate)) {
            if ($counted === 0 || $attemptsLeft === 0) {
                Models::oneTimeTokens()->whereKey($record->getKey())->whereNull('invalidated_at')->update(['invalidated_at' => $now]);
            }

            throw $revealAttempts ? InvalidCode::withAttemptsLeft($counted === 0 ? 0 : $attemptsLeft) : new InvalidCode;
        }

        $claimed = Models::oneTimeTokens()->whereKey($record->getKey())->usable($now)->update(['consumed_at' => $now]);
        $account = $accounts->findByKey($record->account_id);

        if ($claimed === 0 || $account === null || $record->account_type !== $accounts->morphClass()
            || $accounts->normalizeEmail((string) $account->accountEmail()) !== $record->email) {
            throw new InvalidCode;
        }

        return new RedeemedSecret($record, $account);
    }
}
