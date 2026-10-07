<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\Passwords\VerifyPassword;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\LoginFailed;
use RoundlyConsulting\Auth\Exceptions\AuthException;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\Lockout;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * Email/identifier + password. Throttled (identifier+IP, IP, identifier) BEFORE any
 * hashing — the attempt is taken first and given back only once the login is challenged
 * or completes, so concurrent guesses are counted while they hash and a correct password
 * the login then refuses uniformly (`invalid_credentials`: a disabled or unverified account
 * without `reveal_account_state`, a uniform risk denial) keeps its attempt like any wrong
 * one; the password is always checked — against a dummy hash for unknown or
 * passwordless accounts — so neither the response nor its timing reveals whether the
 * account exists. A hard-locked account answers every attempt exactly like a wrong
 * password (`invalid_credentials`, the attempt counted) — a lock never confirms a
 * password nor an account; its owner learns of it from the `AccountLockedNotification`.
 * `locked_until` is read again once the hash is checked, so a lock written while this
 * request hashed holds the same way.
 */
final readonly class AttemptPasswordLogin
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private VerifyPassword $verifyPassword,
        private CompleteFirstFactor $completeFirstFactor,
        private RecordLoginActivity $recordActivity,
        private Lockout $lockout,
    ) {}

    public function execute(string $guard, PasswordCredentials $credentials, SessionContext $context): LoginResult
    {
        $config = $this->guards->get($guard);

        if (! $config->loginMethodEnabled(LoginMethod::Password)) {
            throw new LoginMethodDisabled;
        }

        $kinds = [ThrottleKind::Login, ThrottleKind::LoginIp, ThrottleKind::LoginAccount];

        $this->throttle->attempt($config, $kinds, $credentials->identifier, $context, ActivityType::PasswordLogin);

        $account = (new AccountRepository($config))->findForLogin($credentials->identifier);

        if ($account !== null && $account->isLocked()) {
            // Same cost, answer and throttle accounting as a wrong password: a lock is neither
            // a way around the buckets nor an account-exists oracle. Its owner was mailed.
            $this->verifyPassword->execute(null, $credentials->password);
            $this->fail($guard, $account, $credentials, $context, ActivityOutcome::Locked);

            throw new InvalidCredentials;
        }

        $valid = $this->verifyPassword->execute($account, $credentials->password);

        if ($account !== null && $this->lockedMeanwhile($account)) {
            // A lock written while this request hashed (another guess reached the threshold, an
            // admin) answers exactly like the lock checked above — never a login, never a count.
            $this->fail($guard, $account, $credentials, $context, ActivityOutcome::Locked);

            throw new InvalidCredentials;
        }

        if ($account === null || ! $valid) {
            if ($account !== null) {
                $this->lockout->recordFailure($config, $account);
            }

            $this->fail($guard, $account, $credentials, $context, ActivityOutcome::FailedCredentials);

            throw new InvalidCredentials;
        }

        try {
            $result = $this->completeFirstFactor->execute($config, $account, LoginMethod::Password, $context, [AuthMethodReference::Pwd], $credentials);
        } catch (InvalidCredentials $e) {
            // Refused exactly like a wrong password, so counted like one.
            throw $e;
        } catch (AuthException $e) {
            // Any other refusal already tells a correct password apart: not a guess.
            $this->throttle->release($config, $kinds, $credentials->identifier, $context->ipAddress);

            throw $e;
        }

        // Successes are not counted.
        $this->throttle->release($config, $kinds, $credentials->identifier, $context->ipAddress);

        return $result;
    }

    /**
     * Re-reads `locked_until` alone — the hash just checked stays the one loaded — onto the
     * instance, so every later check sees the lock too.
     */
    private function lockedMeanwhile(Account $account): bool
    {
        $model = AccountModels::of($account);
        $column = Columns::lockedUntil();

        AccountState::reflect($model, [$column => $model->newQuery()->whereKey($model->getKey())->value($column)]);

        return $account->isLocked();
    }

    private function fail(string $guard, ?Account $account, PasswordCredentials $credentials, SessionContext $context, ActivityOutcome $outcome): void
    {
        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::PasswordLogin,
            outcome: $outcome,
            context: $context,
            method: LoginMethod::Password->value,
            reason: $outcome->value,
            account: $account,
            identifier: $credentials->identifier,
        ));

        event(new LoginFailed($guard, $account, LoginMethod::Password, $outcome, $outcome->value, $context));
    }
}
