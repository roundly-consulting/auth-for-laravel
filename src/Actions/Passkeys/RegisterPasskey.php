<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passkeys;

use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegisteredPasskeyData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Events\PasskeyAdded;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Exceptions\PasskeyRegistrationFailed;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Facades\Passkeys;

/**
 * Registers a passkey for a signed-in account, notifies the owner, and applies
 * `invalidation.passkey_changed` (none by default) — returning the re-issued pair when
 * that scope is `others` and a `$current` device was given.
 */
final readonly class RegisterPasskey
{
    public function __construct(
        private GuardRegistry $guards,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, RegistrationResponseData $response, ?string $name = null, ?CurrentToken $current = null, ?SessionContext $context = null): RegisteredPasskeyData
    {
        $config = $this->guards->owning($guard, $account);

        if ($config->passkeyMode() === PasskeyMode::Off) {
            throw new LoginMethodDisabled;
        }

        try {
            $passkey = Passkeys::for(AccountModels::passkeys($account))->register($response, SessionContext::clean($name));
        } catch (PasskeyException $e) {
            throw new PasskeyRegistrationFailed($e);
        }

        event(new PasskeyAdded($guard, $account, (int) $passkey->getKey()));
        $this->notifications->send($config, NotificationType::PasskeyAdded, $account, new NotificationData($guard));

        return new RegisteredPasskeyData($passkey, $this->invalidate->execute($config, $account, InvalidationReason::PasskeyChanged, $current, $context ?? new SessionContext)->tokens);
    }
}
