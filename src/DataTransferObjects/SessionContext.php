<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use DateTimeZone;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Contracts\NegotiatesLocale;
use RoundlyConsulting\Auth\Guards\GuardConfig;

/**
 * Where a request came from: the raw client facts every flow records (IP, user agent,
 * device id/name) and the locale/timezone the account's notifications should use.
 * The package never parses the user agent itself; hosts enrich via events.
 */
final readonly class SessionContext
{
    private const int MAX_DEVICE_LENGTH = 255;

    private const int MAX_USER_AGENT_LENGTH = 1024;

    public function __construct(
        public ?string $ipAddress = null,
        public ?string $userAgent = null,
        public ?string $deviceId = null,
        public ?string $deviceName = null,
        public ?string $locale = null,
        public ?string $timezone = null,
    ) {}

    /**
     * Read the context from a request: `device_name`/`timezone` inputs, the guard's
     * device-id header and its negotiated locale. `ip()` honours the host's TrustProxies.
     */
    public static function fromRequest(Request $request, ?GuardConfig $guard = null): self
    {
        $deviceHeader = $guard?->newDeviceHeader() ?? 'X-Device-Id';
        $deviceName = $request->input('device_name');
        $timezone = $request->input('timezone');
        $userAgent = $request->userAgent();

        return new self(
            ipAddress: $request->ip(),
            userAgent: is_string($userAgent) && $userAgent !== '' ? mb_substr($userAgent, 0, self::MAX_USER_AGENT_LENGTH) : null,
            deviceId: self::clean($request->header($deviceHeader)),
            deviceName: self::clean($deviceName),
            locale: $guard === null ? null : app(NegotiatesLocale::class)->negotiate($request, $guard),
            timezone: is_string($timezone) && in_array($timezone, DateTimeZone::listIdentifiers(), true) ? $timezone : null,
        );
    }

    /**
     * A trimmed, control-character-free, length-capped string, or null.
     */
    public static function clean(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim((string) preg_replace('/[\x00-\x1F\x7F]/u', '', $value));

        return $value === '' ? null : mb_substr($value, 0, self::MAX_DEVICE_LENGTH);
    }
}
