<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Enums\LoginStatus;

/**
 * The outcome of any login step: either a token pair, or a pending challenge the
 * client must continue.
 */
final readonly class LoginResult
{
    public function __construct(
        public LoginStatus $status,
        public ?TokenPair $tokens = null,
        public ?PendingChallenge $challenge = null,
    ) {}

    public static function authenticated(TokenPair $tokens): self
    {
        return new self(LoginStatus::Authenticated, tokens: $tokens);
    }

    public static function challenged(PendingChallenge $challenge): self
    {
        return new self(LoginStatus::ChallengeRequired, challenge: $challenge);
    }

    public function isAuthenticated(): bool
    {
        return $this->status === LoginStatus::Authenticated;
    }

    public function requiresChallenge(): bool
    {
        return $this->status === LoginStatus::ChallengeRequired;
    }
}
