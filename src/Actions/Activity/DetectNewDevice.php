<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Activity;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\FingerprintsDevices;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Models;

/**
 * A device is known when a successful login with its fingerprint exists inside the
 * retention window. The very first successful login is not "new" (`skip_first_login`).
 *
 * Only rows that carry a session count — completed logins and in-session
 * re-authentications. Unauthenticated requests are recorded as "succeeded" too (a reset
 * or sign-in link sent to a known address), and anyone who knows the address can make
 * one from any device.
 *
 * @internal a login-pipeline step (`CompleteLogin`).
 */
final readonly class DetectNewDevice
{
    public function __construct(private FingerprintsDevices $fingerprints) {}

    public function execute(GuardConfig $guard, Account $account, SessionContext $context): bool
    {
        if (! $guard->newDeviceDetectionEnabled() || ! $guard->activityEnabled()) {
            return false;
        }

        $fingerprint = $this->fingerprints->fingerprint($context, $guard);

        if ($fingerprint === null) {
            return false;
        }

        $model = AccountModels::of($account);
        $successes = Models::loginActivities()
            ->where('guard', $guard->name())
            ->where('account_type', $model->getMorphClass())
            ->where('account_id', $model->getKey())
            ->where('outcome', ActivityOutcome::Succeeded->value)
            ->whereNotNull('session_id')
            ->where('created_at', '>=', CarbonImmutable::now()->subDays($guard->activityRetentionDays()));

        if ((clone $successes)->where('device_fingerprint', $fingerprint)->exists()) {
            return false;
        }

        return ! $guard->newDeviceSkipsFirstLogin() || $successes->exists();
    }
}
