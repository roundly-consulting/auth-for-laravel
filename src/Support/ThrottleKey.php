<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use SensitiveParameter;

/**
 * `authentication:{guard}:{kind}:{hmac(identifier)}|{ip}` — identifiers are HMAC'd, so
 * no raw email ever lands in a cache key, and the guard is always part of the key.
 */
final readonly class ThrottleKey
{
    public function __construct(private SecretHasher $hasher) {}

    public function for(GuardConfig $guard, ThrottleKind $kind, #[SensitiveParameter] ?string $identifier, ?string $ip): string
    {
        $id = $identifier === null || $identifier === '' ? '-' : $this->hasher->identifier($guard->name(), mb_strtolower(AccountRepository::compose(trim($identifier))));
        $ip ??= '-';

        $discriminator = match ($kind) {
            ThrottleKind::Login, ThrottleKind::EmailRequest, ThrottleKind::Verification => "{$id}|{$ip}",
            ThrottleKind::LoginIp, ThrottleKind::EmailRequestIp, ThrottleKind::Refresh, ThrottleKind::Registration => $ip,
            ThrottleKind::LoginAccount, ThrottleKind::EmailRequestAccount, ThrottleKind::Reauthentication => $id,
        };

        return "authentication:{$guard->name()}:{$kind->value}:{$discriminator}";
    }

    /**
     * The per-address cooldown on "account exists" notices (`$email` already normalised).
     */
    public function accountExists(GuardConfig $guard, #[SensitiveParameter] string $email): string
    {
        return "authentication:{$guard->name()}:account-exists:".$this->hasher->identifier($guard->name(), $email);
    }
}
