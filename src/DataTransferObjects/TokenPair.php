<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Carbon\CarbonImmutable;
use SensitiveParameter;

/**
 * An access token (jwt-for-laravel) plus its rotating refresh token
 * (refresh-tokens-for-laravel). `sessionId` is the refresh-token family id, carried
 * in the access token as `sid`.
 */
final readonly class TokenPair
{
    public function __construct(
        #[SensitiveParameter] public string $accessToken,
        public CarbonImmutable $accessExpiresAt,
        #[SensitiveParameter] public string $refreshToken,
        public CarbonImmutable $refreshExpiresAt,
        public string $sessionId,
        public string $accessTokenId,
        public string $tokenType = 'Bearer',
    ) {}
}
