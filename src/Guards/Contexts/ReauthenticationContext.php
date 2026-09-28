<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards\Contexts;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Auth\Actions\Account\BeginPasskeyReauthentication;
use RoundlyConsulting\Auth\Actions\Account\EnsureRecentlyAuthenticated;
use RoundlyConsulting\Auth\Actions\Account\Reauthenticate;
use RoundlyConsulting\Auth\Actions\Account\SendReauthenticationCode;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Exceptions\ReauthenticationRequired;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;

/**
 * "Sudo mode" on one guard — `Authentication::reauthentication()` /
 * `Authentication::guard('clients')->reauthentication()`: which proofs an account may
 * use, the proofs themselves, and the checks the HTTP layer runs before a sensitive
 * action. Every method refuses another guard's account first.
 */
final readonly class ReauthenticationContext
{
    use ScopedToGuard;

    public function __construct(
        private GuardConfig $config,
        private Container $container,
    ) {}

    /**
     * The methods this account may re-authenticate with (a second factor, once enrolled,
     * rules out password and email codes).
     *
     * @return list<ReauthenticationMethod>
     */
    public function methods(Account $account): array
    {
        $this->own($account);

        return ReauthenticationMethods::available($this->config, $account);
    }

    /**
     * Mail a re-authentication code (only for accounts that may use one).
     */
    public function sendCode(Account $account, SessionContext $context): void
    {
        $this->own($account);

        $this->make(SendReauthenticationCode::class)->execute($this->guardName(), $account, $context);
    }

    /**
     * Passkey request options bound to the account and to `$current`'s session.
     */
    public function passkeyOptions(Account $account, CurrentToken $current): RequestOptionsData
    {
        $this->own($account);

        return $this->make(BeginPasskeyReauthentication::class)->execute($this->guardName(), $account, $current);
    }

    /**
     * Re-prove the account; its session counts as recently authenticated until the
     * returned time.
     */
    public function confirm(Account $account, ReauthenticationData $data): CarbonImmutable
    {
        $this->own($account);

        return $this->make(Reauthenticate::class)->execute($this->guardName(), $account, $data);
    }

    /**
     * Require a recent re-authentication of `$current`'s session (default window:
     * `reauthentication.timeout`).
     *
     * @throws ReauthenticationRequired
     */
    public function ensureRecent(Account $account, CurrentToken $current, ?int $seconds = null): void
    {
        $this->own($account);

        $this->make(EnsureRecentlyAuthenticated::class)->execute($this->guardName(), $current, $account, $seconds);
    }

    /**
     * The HTTP layer's gate for a sensitive action: a recent re-authentication when the
     * guard lists it in `reauthentication.required_for`, nothing otherwise. Call it before
     * `twoFactor()->disable()`, `passkeys()->remove()`, `email()->requestChange()` … when
     * acting for the signed-in user.
     *
     * @throws ReauthenticationRequired
     */
    public function ensureFor(SensitiveAction $action, Account $account, CurrentToken $current): void
    {
        $this->own($account);

        $this->make(SensitiveActionGate::class)->check($this->config, $action, $current, $account);
    }
}
