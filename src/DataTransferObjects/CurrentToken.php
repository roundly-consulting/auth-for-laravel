<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Jwt\Facades\Jwt;
use RoundlyConsulting\Jwt\Jose\Claims;

/**
 * The access token the current request authenticated with.
 */
final readonly class CurrentToken
{
    /**
     * @param  list<AuthMethodReference>  $authMethods  the login's `amr` (unknown values dropped)
     */
    public function __construct(
        public string $jti,
        public CarbonImmutable $expiresAt,
        public ?string $sessionId = null,
        public ?CarbonImmutable $authTime = null,
        public array $authMethods = [],
    ) {}

    public static function fromClaims(Claims $claims): self
    {
        $authTime = $claims->authTime();

        return new self(
            jti: $claims->string('jti'),
            expiresAt: CarbonImmutable::createFromTimestamp($claims->int('exp')),
            sessionId: $claims->sessionId(),
            authTime: $authTime === null ? null : CarbonImmutable::createFromTimestamp($authTime),
            authMethods: AuthMethodReference::fromValues($claims->get('amr')),
        );
    }

    /**
     * @throws AuthenticationException when the request is not authenticated on the guard
     */
    public static function fromRequest(Request $request, GuardConfig $guard): self
    {
        $claims = Jwt::claims($guard->laravelGuard());

        if ($claims === null) {
            throw new AuthenticationException(guards: [$guard->laravelGuard()]);
        }

        return self::fromClaims($claims);
    }

    /**
     * The key a per-session marker (re-authentication, ceremony binding) is stored under.
     */
    public function sessionKey(): string
    {
        return $this->sessionId ?? $this->jti;
    }
}
