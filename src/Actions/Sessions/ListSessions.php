<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Sessions;

use BackedEnum;
use Carbon\CarbonImmutable;
use Illuminate\Support\Collection;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionData;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\RefreshTokens\Facades\RefreshTokens;
use RoundlyConsulting\RefreshTokens\Models\RefreshToken as RefreshTokenModel;

/**
 * The account's active device sessions (one per refresh-token family), newest first.
 * "Last used" is the last login/refresh — no per-request writes.
 */
final readonly class ListSessions
{
    public function __construct(private GuardRegistry $guards) {}

    /**
     * @return Collection<int, SessionData>
     */
    public function execute(string $guard, Account $account, ?string $currentSessionId = null): Collection
    {
        $this->guards->get($guard);

        return RefreshTokens::sessions(AccountModels::of($account))->all()
            ->map(static function (RefreshTokenModel $row) use ($currentSessionId): SessionData {
                $meta = $row->meta ?? [];
                $deviceType = $row->device_type;

                return new SessionData(
                    id: $row->family_id,
                    deviceName: is_string($meta['device_name'] ?? null) ? $meta['device_name'] : null,
                    ipAddress: $row->ip_address,
                    userAgent: $row->user_agent,
                    browser: $row->browser,
                    os: $row->os,
                    deviceType: $deviceType instanceof BackedEnum ? (string) $deviceType->value : $deviceType,
                    country: $row->country,
                    city: $row->city,
                    authMethods: array_values(array_filter(is_array($meta['amr'] ?? null) ? $meta['amr'] : [], 'is_string')),
                    startedAt: CarbonImmutable::instance($row->family_started_at ?? $row->created_at),
                    lastUsedAt: CarbonImmutable::instance($row->created_at),
                    expiresAt: $row->expires_at,
                    current: $currentSessionId !== null && $row->family_id === $currentSessionId,
                );
            })
            ->values();
    }
}
