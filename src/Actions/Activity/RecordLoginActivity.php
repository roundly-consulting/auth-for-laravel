<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Activity;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\FingerprintsDevices;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\Enums\IdentifierStorage;
use RoundlyConsulting\Auth\Events\LoginActivityRecorded;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\SecretHasher;

/**
 * Writes one login-activity row (when the guard's activity log is on) and dispatches
 * {@see LoginActivityRecorded} — ids only — for host enrichment.
 *
 * @internal the activity recorder every flow calls; read rows through `activity()`.
 */
final readonly class RecordLoginActivity
{
    public function __construct(
        private GuardRegistry $guards,
        private FingerprintsDevices $fingerprints,
        private SecretHasher $hasher,
    ) {}

    public function execute(LoginActivityData $data): ?LoginActivity
    {
        $guard = $this->guards->get($data->guard);

        if (! $guard->activityEnabled()) {
            return null;
        }

        $identifier = match (true) {
            $data->identifier === null || $data->identifier === '' => null,
            $guard->identifierStorage() === IdentifierStorage::Plain => mb_substr($data->identifier, 0, 255),
            // Normalised exactly like the throttle key: one address, one hash, however it was typed.
            $guard->identifierStorage() === IdentifierStorage::Hash => $this->hasher->identifier($guard->name(), mb_strtolower(AccountRepository::compose(trim($data->identifier)))),
            default => null,
        };

        $account = $data->account instanceof Model ? $data->account : null;

        $activity = Models::loginActivities()->create([
            'guard' => $guard->name(),
            'account_type' => $account?->getMorphClass(),
            'account_id' => $account?->getKey(),
            'type' => $data->type,
            'outcome' => $data->outcome,
            'method' => $data->method,
            'reason' => $data->reason === null ? null : mb_substr($data->reason, 0, 64),
            'identifier' => $identifier,
            'ip_address' => $data->context->ipAddress,
            'user_agent' => $data->context->userAgent,
            'device_fingerprint' => $this->fingerprints->fingerprint($data->context, $guard),
            'session_id' => $data->sessionId,
            'challenge_id' => $data->challengeId,
            'is_new_device' => $data->newDevice,
        ]);

        event(new LoginActivityRecorded((int) $activity->getKey(), $guard->name()));

        return $activity;
    }
}
