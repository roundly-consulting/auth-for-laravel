<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Account;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Exceptions\FactorNotAllowed;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\ReauthenticationMarker;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Facades\Passkeys;

/**
 * Options for a re-authentication passkey ceremony: bound to the account (only its
 * credentials can answer) and to the calling session (the ceremony id is remembered
 * per `sid` and must come back with the assertion).
 */
final readonly class BeginPasskeyReauthentication
{
    public function __construct(
        private GuardRegistry $guards,
        private ReauthenticationMarker $marker,
    ) {}

    public function execute(string $guard, Account $account, CurrentToken $current): RequestOptionsData
    {
        $config = $this->guards->get($guard);

        if (! in_array(ReauthenticationMethod::Passkey, ReauthenticationMethods::available($config, $account), true)) {
            throw new FactorNotAllowed;
        }

        $options = Passkeys::authenticationOptions(AccountModels::passkeys($account));

        $this->marker->bindCeremony($guard, $current->sessionKey(), $options->ceremonyId, $config->challengeTtl());

        return $options;
    }
}
