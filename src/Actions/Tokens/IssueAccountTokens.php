<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Tokens;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Events\TokensIssued;
use RoundlyConsulting\Auth\Guards\GuardRegistry;

/**
 * Issues a pair from host code — impersonation, an SSO callback, tests. The caller
 * vouches for the authentication (`amr` defaults to none). Another guard's account is
 * refused before anything is minted, and the pair is announced (`TokensIssued`) like
 * every other login.
 */
final readonly class IssueAccountTokens
{
    public function __construct(
        private GuardRegistry $guards,
        private IssueTokenPair $issueTokenPair,
    ) {}

    /**
     * @param  list<AuthMethodReference>  $authMethods
     */
    public function execute(string $guard, Account $account, SessionContext $context, LoginMethod $method = LoginMethod::Host, array $authMethods = []): TokenPair
    {
        $config = $this->guards->owning($guard, $account);

        $tokens = $this->issueTokenPair->execute($config, $account, $method, $authMethods, $context);

        event(new TokensIssued($guard, $account, $tokens->sessionId, $tokens->accessTokenId, $method));

        return $tokens;
    }
}
