<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Login;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\Tokens\IssueTokenPair;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\PendingLogin;
use RoundlyConsulting\Auth\DataTransferObjects\RiskAssessment;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Events\LoginSucceeded;
use RoundlyConsulting\Auth\Events\NewDeviceDetected;
use RoundlyConsulting\Auth\Events\SuspiciousLoginDetected;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountState;
use RoundlyConsulting\Auth\Support\Columns;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;

/**
 * The success tail of every login — straight after the first factor or when a challenge
 * finalizes: issue the pair, stamp `last_login_at`, record the activity, dispatch the
 * events, and send the new-device / risk notifications (only now that the login is
 * complete).
 *
 * @internal the success tail of every login; log in through the guard context.
 */
final readonly class CompleteLogin
{
    public function __construct(
        private GuardRegistry $guards,
        private IssueTokenPair $issueTokenPair,
        private RecordLoginActivity $recordActivity,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(PendingLogin $login): TokenPair
    {
        $guard = $this->guards->get($login->guard);
        $account = $login->account;
        $now = CarbonImmutable::now();

        $tokens = $this->issueTokenPair->execute($guard, $account, $login->method, $login->authMethods, $login->context, $login->authTime);

        AccountState::write($account, [Columns::lastLoginAt() => $now]);

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard->name(),
            type: $login->method->activityType(),
            outcome: ActivityOutcome::Succeeded,
            context: $login->context,
            method: $login->method->value,
            account: $account,
            identifier: $login->identifier,
            sessionId: $tokens->sessionId,
            challengeId: $login->challengeId,
            newDevice: $login->newDevice,
        ));

        event(new LoginSucceeded($guard->name(), $account, $login->method, $tokens->sessionId, $login->context));
        event(new TokensIssued($guard->name(), $account, $tokens->sessionId, $tokens->accessTokenId, $login->method));

        if ($login->newDevice) {
            event(new NewDeviceDetected($guard->name(), $account, $login->context));

            $this->notifications->send($guard, NotificationType::NewDevice, $account, new NotificationData(
                guard: $guard->name(),
                replacements: [
                    'ip' => $login->context->ipAddress ?? '-',
                    'user_agent' => $login->context->userAgent ?? '-',
                    'time' => $now->setTimezone($account->accountTimezone() ?? 'UTC')->format('Y-m-d H:i T'),
                ],
            ));
        }

        if ($login->notifyRisk) {
            event(new SuspiciousLoginDetected($guard->name(), $account, new RiskAssessment($login->riskLevel), $login->context));

            $this->notifications->send($guard, NotificationType::UnusualSignIn, $account, new NotificationData($guard->name()));
        }

        return $tokens;
    }
}
