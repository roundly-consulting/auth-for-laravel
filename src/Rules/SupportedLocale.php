<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\AcceptLanguage;

/**
 * A BCP-47-shaped tag that is one of the guard's `locale.supported`.
 */
final readonly class SupportedLocale implements ValidationRule
{
    public function __construct(private GuardConfig $guard) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value) || strlen($value) > 12 || AcceptLanguage::match($value, $this->guard->supportedLocales()) !== $value) {
            $fail('authentication::validation.locale')->translate();
        }
    }
}
