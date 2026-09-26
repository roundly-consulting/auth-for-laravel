<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;

/**
 * `{email, password?, attributes?}` — `attributes` are the host's extra fields, validated
 * and allow-listed by its `registration.rules`.
 */
final class RegisterRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'email' => ['required', 'string', 'max:255'],
            'password' => ['nullable', 'string', 'max:1024'],
            'attributes' => ['nullable', 'array'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): RegistrationData
    {
        return new RegistrationData(
            email: $this->validatedString('email'),
            password: $this->validatedNullableString('password'),
            context: $this->sessionContext(),
            attributes: $this->validatedArray('attributes'),
        );
    }
}
