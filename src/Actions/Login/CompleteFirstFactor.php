<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Auth\Actions\Activity\AssessLoginRisk;
use RoundlyConsulting\Auth\Actions\Activity\DetectNewDevice;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\Challenges\ResolveRequiredSteps;
use RoundlyConsulting\Auth\Actions\Challenges\StartLoginChallenge;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\LoginRiskContext;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\PendingLogin;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\RiskReaction;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\LoginChallenged;
use RoundlyConsulting\Auth\Events\LoginFailed;
use RoundlyConsulting\Auth\Events\PasswordRehashed;
use RoundlyConsulting\Auth\Events\SuspiciousLoginDetected;
use RoundlyConsulting\Auth\Exceptions\EnrolmentRequired;
use RoundlyConsulting\Auth\Exceptions\InvalidCredentials;
use RoundlyConsulting\Auth\Exceptions\LoginDenied;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\Lockout;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * The hub every primary method ends in, in this exact order:
 *
 *  1. possession side effects (an email login verifies the address);
 *  2. account state — disabled / locked / unverified (only now, after a verified factor);
 *  3. password rehash;
 *  4. locale fill;
 *  5. new-device detection (notified only once the login completes);
 *  6. risk assessment — deny, notify, or require a second factor;
 *  7. required steps; only now — the password is about to be confirmed by a challenge or a
 *     login — reset the lockout counter and clear the login bucket (a uniform refusal above
 *     must leave both exactly as a wrong password would);
 *  8. a challenge, or the success tail.
 *
 * @internal the shared login pipeline behind every first factor; log in through the guard context.
 */
final readonly class CompleteFirstFactor
{
    public function __construct(
        private EnsureAccountCanLogin $ensureCanLogin,
        private DetectNewDevice $detectNewDevice,
        private AssessLoginRisk $assessRisk,
        private ResolveRequiredSteps $resolveSteps,
        private StartLoginChallenge $startChallenge,
        private CompleteLogin $completeLogin,
        private RecordLoginActivity $recordActivity,
        private NotificationDispatcher $notifications,
        private Throttle $throttle,
        private Lockout $lockout,
    ) {}

    /**
     * @param  list<AuthMethodReference>  $authMethods  what the first factor proved
     */
    public function execute(
        GuardConfig $guard,
        Account $account,
        LoginMethod $method,
        SessionContext $context,
        array $authMethods,
        ?PasswordCredentials $credentials = null,
    ): LoginResult {
        $now = CarbonImmutable::now();
        $identifier = $credentials !== null ? $credentials->identifier : $account->accountEmail();

        // 1. Possession side effects.
        if (in_array($method, [LoginMethod::MagicLink, LoginMethod::EmailOtp], true)
            && $guard->verifiesEmailOnEmailLogin() && ! $account->hasVerifiedEmail()) {
            $account->markEmailAsVerified();
        }

        // 2. Account state.
        $this->ensureCanLogin->execute($guard, $account, $method, $context, $identifier);

        // 3. Password rehash.
        if ($credentials !== null) {
            $this->rehash($guard, $account, $credentials);
        }

        // 4. Locale fill.
        if ($guard->fillsLocaleOnLogin() && $account->accountLocale() === null && $context->locale !== null) {
            AccountState::write($account, [Columns::locale() => $context->locale]);
        }

        // 5. New device (notified after completion).
        $newDevice = $this->detectNewDevice->execute($guard, $account, $context);

        // 6. Risk.
        $assessment = $this->assessRisk->execute(new LoginRiskContext($guard, $account, $method, $context, $newDevice));
        $reaction = $guard->riskReaction($assessment->level);

        if ($reaction === RiskReaction::Deny) {
            event(new SuspiciousLoginDetected($guard->name(), $account, $assessment, $context));
            $this->notifications->send($guard, NotificationType::SignInBlocked, $account, new NotificationData($guard->name()));
            $this->deny($guard, $account, $method, $context, $identifier, 'risk');
        }

        $pending = new PendingLogin(
            guard: $guard->name(),
            account: $account,
            method: $method,
            authMethods: $authMethods,
            authTime: $now,
            context: $context,
            newDevice: $newDevice,
            riskLevel: $assessment->level,
            notifyRisk: $reaction === RiskReaction::Notify,
            identifier: $identifier,
        );

        // 7. Required steps.
        try {
            $steps = $this->resolveSteps->execute($guard, $account, $method, $reaction);
        } catch (LoginDenied) {
            event(new SuspiciousLoginDetected($guard->name(), $account, $assessment, $context));
            $this->deny($guard, $account, $method, $context, $identifier, 'step_up_unavailable');
        }

        // The password is confirmed from here on — by a challenge or a login — so the lockout
        // counter and the login bucket start over.
        if ($credentials !== null) {
            $this->lockout->reset($guard, $account);
            $this->throttle->clear($guard, ThrottleKind::Login, $credentials->identifier, $context->ipAddress);
        }

        // 8. A challenge, or the success tail.
        if ($steps !== []) {
            return $this->challenge($guard, $pending, $steps);
        }

        return LoginResult::authenticated($this->completeLogin->execute($pending));
    }

    /**
     * @param  list<ChallengeRequirement>  $steps
     */
    private function challenge(GuardConfig $guard, PendingLogin $pending, array $steps): LoginResult
    {
        $enrols = array_filter($steps, static fn (ChallengeRequirement $requirement): bool => $requirement->step->isEnrolment()) !== [];

        if ($enrols && (! $guard->allowsEnrolmentInChallenge()
            || ($guard->enrolmentRequiresVerifiedEmail() && ! $pending->account->hasVerifiedEmail()))) {
            $this->record($guard, $pending->account, $pending->method, $pending->context, $pending->identifier, ActivityOutcome::Denied, 'enrolment_required');

            throw new EnrolmentRequired;
        }

        $challenge = $this->startChallenge->execute($pending, $steps);

        $this->record($guard, $pending->account, $pending->method, $pending->context, $pending->identifier, ActivityOutcome::Challenged, null, $challenge->challengeId);

        event(new LoginChallenged($guard->name(), $pending->account, (int) $challenge->challengeId, $steps));

        return LoginResult::challenged($challenge);
    }

    private function rehash(GuardConfig $guard, Account $account, PasswordCredentials $credentials): void
    {
        $model = AccountModels::of($account);
        $hash = $model->getAttribute(Columns::password());

        if ($guard->rehashesPasswordsOnLogin() && is_string($hash) && Hash::needsRehash($hash)) {
            AccountState::write($account, [Columns::password() => Hash::make($credentials->password)]);

            event(new PasswordRehashed($guard->name(), $account));
        }
    }

    private function deny(GuardConfig $guard, Account $account, LoginMethod $method, SessionContext $context, ?string $identifier, string $reason): never
    {
        $this->record($guard, $account, $method, $context, $identifier, ActivityOutcome::Denied, $reason);

        event(new LoginFailed($guard->name(), $account, $method, ActivityOutcome::Denied, $reason, $context));

        throw $guard->riskDenialIsUniform() ? new InvalidCredentials : new LoginDenied;
    }

    private function record(GuardConfig $guard, Account $account, LoginMethod $method, SessionContext $context, ?string $identifier, ActivityOutcome $outcome, ?string $reason, ?int $challengeId = null): void
    {
        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard->name(),
            type: $method->activityType(),
            outcome: $outcome,
            context: $context,
            method: $method->value,
            reason: $reason,
            account: $account,
            identifier: $identifier,
            challengeId: $challengeId,
        ));
    }
}
