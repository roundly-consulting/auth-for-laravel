<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use RoundlyConsulting\Auth\Contracts\ChecksBreachedPasswords;
use RoundlyConsulting\Auth\Exceptions\BreachCheckUnavailable;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use SensitiveParameter;

/**
 * The guard's password policy: Laravel's own `Password` rule for length and
 * composition (NIST-style defaults: length, no composition), plus
 *
 *  - a 72-BYTE cap under bcrypt, which otherwise silently truncates;
 *  - "must not contain the email's local part";
 *  - the optional breached-password check through {@see ChecksBreachedPasswords}
 *    (short timeout, fail-open unless `fail_closed`).
 */
final readonly class PasswordPolicy implements ValidationRule
{
    public const int BCRYPT_MAX_BYTES = 72;

    public function __construct(
        private GuardConfig $guard,
        private ?string $email = null,
    ) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value)) {
            $fail('validation.string')->translate();

            return;
        }

        $composition = Validator::make([$attribute => $value], [$attribute => [$this->laravelRule()]]);

        foreach ($composition->errors()->all() as $message) {
            $fail($message);
        }

        if (config('hashing.driver') === 'bcrypt' && strlen($value) > self::BCRYPT_MAX_BYTES) {
            $fail('authentication::validation.password.too_long_bytes')->translate(['max' => self::BCRYPT_MAX_BYTES]);
        }

        if ($this->containsIdentifier($value)) {
            $fail('authentication::validation.password.contains_identifier')->translate();
        }

        if ($composition->errors()->isEmpty() && $this->guard->breachCheckEnabled()) {
            $this->checkBreached($value, $fail);
        }
    }

    private function laravelRule(): Password
    {
        $rule = Password::min($this->guard->passwordMinLength())->max($this->guard->passwordMaxLength());

        if ($this->guard->passwordRequiresLetters()) {
            $rule->letters();
        }

        if ($this->guard->passwordRequiresMixedCase()) {
            $rule->mixedCase();
        }

        if ($this->guard->passwordRequiresNumbers()) {
            $rule->numbers();
        }

        if ($this->guard->passwordRequiresSymbols()) {
            $rule->symbols();
        }

        return $rule;
    }

    private function containsIdentifier(#[SensitiveParameter] string $password): bool
    {
        if (! $this->guard->passwordMustNotContainIdentifier() || $this->email === null) {
            return false;
        }

        $local = mb_strtolower(explode('@', $this->email)[0]);

        return mb_strlen($local) >= 3 && str_contains(mb_strtolower($password), $local);
    }

    private function checkBreached(#[SensitiveParameter] string $password, Closure $fail): void
    {
        try {
            if (app(ChecksBreachedPasswords::class)->isBreached($password, $this->guard)) {
                $fail('authentication::validation.password.breached')->translate();
            }
        } catch (BreachCheckUnavailable) {
            $fail('authentication::validation.password.unavailable')->translate();
        }
    }
}
