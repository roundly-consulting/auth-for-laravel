<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards\Contexts;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Guards\AccountRepository;

/**
 * @internal the plumbing every guard context shares: its guard's name, the ownership
 * refusal each account-taking method runs FIRST, and container resolution — so a host's
 * rebinding of an action applies to the facade too. Expects `$config` and `$container`.
 */
trait ScopedToGuard
{
    private function guardName(): string
    {
        return $this->config->name();
    }

    /**
     * Refuse an account of another guard's model before anything happens.
     *
     * @throws AuthenticationMisconfigured
     */
    private function own(Account $account): void
    {
        (new AccountRepository($this->config))->ensureOwns($account);
    }

    /**
     * @template TClass of object
     *
     * @param  class-string<TClass>  $class
     * @return TClass
     */
    private function make(string $class): object
    {
        return $this->container->make($class);
    }
}
