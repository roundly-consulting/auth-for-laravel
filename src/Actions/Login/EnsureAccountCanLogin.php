<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Events\LoginFailed;
use RoundlyConsulting\Auth\Exceptions\AccountDisabled;
use RoundlyConsulting\Auth\Exceptions\AuthException;
use RoundlyConsulting\Auth\Exceptions\EmailNotVerified;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\Lockout;

/**
 * Account-state checks, run only AFTER a verified first factor (and again when a
 * challenge finalizes): disabled, locked, unverified. A lock answers
 * {@see TooManyAttempts} — never `account_locked` — so a correct password is not
 * confirmed; `login.reveal_account_state = false` makes every state uniform
 * `invalid_credentials`.
 */
final readonly class EnsureAccountCanLogin
{
    public function __construct(private RecordLoginActivity $recordActivity) {}

    /**
     * @throws AuthException
     */
    public function execute(GuardConfig $guard, Account $account, LoginMethod $method, SessionContext $context, ?string $identifier = null): void
    {
        if ($account->isDisabled()) {
            $this->fail($guard, $account, $method, $context, $identifier, ActivityOutcome::Disabled, $guard->revealAccountState() ? new AccountDisabled : new InvalidCredentials);
        }

        if ($account->isLocked()) {
            $this->fail($guard, $account, $method, $context, $identifier, ActivityOutcome::Locked, TooManyAttempts::retryAfter(Lockout::secondsRemaining($account)));
        }

        if ($guard->verificationMode() === EmailVerificationMode::RequiredForLogin && ! $account->hasVerifiedEmail()) {
            $this->fail($guard, $account, $method, $context, $identifier, ActivityOutcome::Unverified, $guard->revealAccountState() ? new EmailNotVerified : new InvalidCredentials);
        }
    }

    private function fail(
        GuardConfig $guard,
        Account $account,
        LoginMethod $method,
        SessionContext $context,
        ?string $identifier,
        ActivityOutcome $outcome,
        AuthException $exception,
    ): never {
        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard->name(),
            type: $method->activityType(),
            outcome: $outcome,
            context: $context,
            method: $method->value,
            reason: $outcome->value,
            account: $account,
            identifier: $identifier,
        ));

        event(new LoginFailed($guard->name(), $account, $method, $outcome, $outcome->value, $context));

        throw $exception;
    }
}
