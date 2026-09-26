<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

/**
 * The host-controlled part of an access token. `extra` is an open claim map — it IS a
 * JSON payload — and can never override the registered/known claims.
 */
final readonly class AccessTokenClaims
{
    /**
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $extra
     */
    public function __construct(
        public ?string $email = null,
        public bool $emailVerified = false,
        public array $permissions = [],
        public array $extra = [],
    ) {}
}
