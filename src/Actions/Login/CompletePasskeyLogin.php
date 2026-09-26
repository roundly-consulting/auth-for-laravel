<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use Illuminate\Contracts\Cache\Repository as Cache;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\LoginFailed;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\Throttle;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Facades\Passkeys;

/**
 * Completes a passwordless passkey login. The assertion must answer a ceremony THIS
 * guard's login endpoint started, and the credential must belong to this guard's model
 * (checked by passkeys before any sign-count write — a clients passkey on the users
 * endpoint changes nothing). Every failure is a uniform `invalid_credentials`.
 */
final readonly class CompletePasskeyLogin
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private Cache $cache,
        private CompleteFirstFactor $completeFirstFactor,
        private RecordLoginActivity $recordActivity,
    ) {}

    public function execute(string $guard, AuthenticationResponseData $response, SessionContext $context): LoginResult
    {
        $config = $this->guards->get($guard);

        if (! $config->loginMethodEnabled(LoginMethod::Passkey)) {
            throw new LoginMethodDisabled;
        }

        $this->throttle->ensure($config, [ThrottleKind::LoginIp], null, $context, ActivityType::PasskeyLogin);

        $accounts = new AccountRepository($config);
        $ceremony = $response->ceremonyId === null ? null : $this->cache->pull(BeginPasskeyLogin::key($guard, $response->ceremonyId));

        if (! is_string($ceremony)) {
            $this->fail($config->name(), $context);
        }

        try {
            $passkey = Passkeys::authenticate($response, AuthenticationExpectation::ownerType($accounts->morphClass()));
        } catch (PasskeyException) {
            $this->fail($config->name(), $context);
        }

        $account = $accounts->findByKey($passkey->authenticatable_id);

        if ($account === null) {
            $this->fail($config->name(), $context);
        }

        $amr = [AuthMethodReference::Hwk, AuthMethodReference::User];

        if ($ceremony === 'uv') {
            $amr[] = AuthMethodReference::Mfa;
        }

        return $this->completeFirstFactor->execute($config, $account, LoginMethod::Passkey, $context, $amr);
    }

    private function fail(string $guard, SessionContext $context): never
    {
        $config = $this->guards->get($guard);

        $this->throttle->hit($config, [ThrottleKind::LoginIp], null, $context->ipAddress);

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::PasskeyLogin,
            outcome: ActivityOutcome::FailedCredentials,
            context: $context,
            method: LoginMethod::Passkey->value,
        ));

        event(new LoginFailed($guard, null, LoginMethod::Passkey, ActivityOutcome::FailedCredentials, 'passkey', $context));

        throw new InvalidCredentials;
    }
}
