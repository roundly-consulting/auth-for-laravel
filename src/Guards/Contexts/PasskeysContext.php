<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards\Contexts;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Collection;
use RoundlyConsulting\Auth\Actions\Passkeys\BeginPasskeyRegistration;
use RoundlyConsulting\Auth\Actions\Passkeys\ListPasskeys;
use RoundlyConsulting\Auth\Actions\Passkeys\RegisterPasskey;
use RoundlyConsulting\Auth\Actions\Passkeys\RemovePasskey;
use RoundlyConsulting\Auth\Actions\Passkeys\RenamePasskey;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\RegisteredPasskeyData;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * An account's passkeys on one guard — `Authentication::passkeys()` /
 * `Authentication::guard('clients')->passkeys()`. Every method refuses another guard's
 * account before it writes; a passkey of another account is `PasskeyNotFound`. Changes
 * notify the owner and apply `invalidation.passkey_changed` (none by default).
 *
 * The HTTP layer demands a recent re-authentication to register or remove one — host
 * code acting for the user vouches for it, or calls `reauthentication()->ensureFor()`.
 */
final readonly class PasskeysContext
{
    use ScopedToGuard;

    public function __construct(
        private GuardConfig $config,
        private Container $container,
    ) {}

    /**
     * The account's active passkeys, newest first.
     *
     * @return Collection<int, Passkey>
     */
    public function all(Account $account): Collection
    {
        $this->own($account);

        return $this->make(ListPasskeys::class)->execute($this->guardName(), $account);
    }

    /**
     * WebAuthn creation options for a new passkey of this account.
     */
    public function registrationOptions(Account $account): CreationOptionsData
    {
        $this->own($account);

        return $this->make(BeginPasskeyRegistration::class)->execute($this->guardName(), $account);
    }

    /**
     * Verify the authenticator's response and store the passkey.
     */
    public function register(Account $account, RegistrationResponseData $response, ?string $name = null, ?CurrentToken $current = null, ?SessionContext $context = null): RegisteredPasskeyData
    {
        $this->own($account);

        return $this->make(RegisterPasskey::class)->execute($this->guardName(), $account, $response, $name, $current, $context);
    }

    /**
     * Rename one of the account's passkeys (cosmetic).
     */
    public function rename(Account $account, Passkey|int $passkey, string $name): Passkey
    {
        $this->own($account);

        return $this->make(RenamePasskey::class)->execute($this->guardName(), $account, self::id($passkey), $name);
    }

    /**
     * Remove one of the account's passkeys — refused for the last way in.
     */
    public function remove(Account $account, Passkey|int $passkey, ?CurrentToken $current = null, ?SessionContext $context = null): ?TokenPair
    {
        $this->own($account);

        return $this->make(RemovePasskey::class)->execute($this->guardName(), $account, self::id($passkey), $current, $context);
    }

    private static function id(Passkey|int $passkey): int
    {
        return $passkey instanceof Passkey ? (int) $passkey->getKey() : $passkey;
    }
}
