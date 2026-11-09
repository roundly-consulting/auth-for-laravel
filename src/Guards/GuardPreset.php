<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards;

/**
 * Ready-made guard blocks for `config/authentication.php`. Each returns the settings it
 * stands for, with the guard's own overrides merged on top (associative arrays merge,
 * lists replace — like `defaults` and `guards.<name>`):
 *
 * ```php
 * 'guards' => [
 *     'users' => GuardPreset::hardened(['model' => App\Models\User::class]),
 * ],
 * ```
 *
 * The values are the defaults planned for the next major release, so a guard on the
 * preset already behaves as it will then.
 */
final class GuardPreset
{
    /**
     * No account enumeration through registration, no sign-in before the address is
     * proven, a hard lock after repeated failures, and no way in for whoever registered
     * an address before its owner did.
     *
     * @param  array<array-key, mixed>  $overrides  the guard's own settings, nested like the config
     * @return array<array-key, mixed>
     */
    public static function hardened(array $overrides = []): array
    {
        return ConfigMerger::merge(self::hardenedSettings(), $overrides);
    }

    /**
     * @return array<string, mixed>
     */
    private static function hardenedSettings(): array
    {
        return [
            'registration' => [
                'uniform_response' => true,
            ],
            'verification' => [
                'mode' => 'required_for_login',
                'verify_on_email_login' => true,
                'secure_on_email_login' => true,
            ],
            'lockout' => [
                'enabled' => true,
            ],
        ];
    }
}
