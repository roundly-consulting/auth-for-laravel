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
            ->where('created_at', '>=', CarbonImmutable::now()->subDays($guard->activityRetentionDays()));

        if ((clone $successes)->where('device_fingerprint', $fingerprint)->exists()) {
            return false;
        }

        return ! $guard->newDeviceSkipsFirstLogin() || $successes->exists();
    }
}
