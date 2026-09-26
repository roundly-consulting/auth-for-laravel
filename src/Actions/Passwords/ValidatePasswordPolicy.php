<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passwords;

use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Rules\PasswordPolicy;
use SensitiveParameter;

/**
 * Applies the guard's password policy on every password-SETTING path (registration,
 * invitation acceptance, reset, change, set). Throws a validation error on `password`.
 */
final class ValidatePasswordPolicy
{
    /**
     * @throws ValidationException
     */
    public function execute(GuardConfig $guard, #[SensitiveParameter] string $password, ?Account $account = null, ?string $email = null): void
    {
        Validator::make(
            ['password' => $password],
            ['password' => ['required', 'string', new PasswordPolicy($guard, $email ?? $account?->accountEmail())]],
        )->validate();
    }
}
