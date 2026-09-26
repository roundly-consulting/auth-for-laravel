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
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Exceptions\TooManyAttempts;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Lockout;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * Email/identifier + password. Throttled (identifier+IP, IP, identifier) BEFORE any
 * hashing — the attempt is taken first and given back only when the password proves
 * valid, so concurrent guesses are counted while they hash; the password is always checked — against a dummy hash for unknown or
 * passwordless accounts — so neither the response nor its timing reveals whether the
 * account exists. A hard-locked account answers every attempt with `too_many_attempts`.
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
            $this->verifyPassword->execute(null, $credentials->password);
            $this->throttle->release($config, $kinds, $credentials->identifier, $context->ipAddress);
            $this->fail($guard, $account, $credentials, $context, ActivityOutcome::Locked);

            throw TooManyAttempts::retryAfter(Lockout::secondsRemaining($account));
        }

        $valid = $this->verifyPassword->execute($account, $credentials->password);

        if ($account === null || ! $valid) {
            if ($account !== null) {
                $this->lockout->recordFailure($config, $account);
            }

            $this->fail($guard, $account, $credentials, $context, ActivityOutcome::FailedCredentials);

            throw new InvalidCredentials;
        }

        // Successes are not counted.
        $this->throttle->release($config, $kinds, $credentials->identifier, $context->ipAddress);

        return $this->completeFirstFactor->execute($config, $account, LoginMethod::Password, $context, [AuthMethodReference::Pwd], $credentials);
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
