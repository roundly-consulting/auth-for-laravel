<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Http\RequestGuard;

/**
 * Base of the package's form requests: guard + session-context helpers, and typed
 * accessors over `validated()` (never `all()`).
 */
abstract class AuthenticationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function guardConfig(): GuardConfig
    {
        return RequestGuard::config($this);
    }

    public function sessionContext(): SessionContext
    {
        return SessionContext::fromRequest($this, $this->guardConfig());
    }

    protected function validatedString(string $key): string
    {
        $value = $this->validated($key);

        return is_string($value) ? $value : '';
    }

    protected function validatedNullableString(string $key): ?string
    {
        $value = $this->validated($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    protected function validatedArray(string $key): array
    {
        $value = $this->validated($key);

        return is_array($value) ? $value : [];
    }
}
