<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\PasskeyRegistrationData;
use RoundlyConsulting\Auth\Http\Requests\Concerns\ParsesPasskeyCredentials;

final class RegisterPasskeyRequest extends AuthenticationRequest
{
    use ParsesPasskeyCredentials;

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'credential' => ['required', 'array'],
            'name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): PasskeyRegistrationData
    {
        return new PasskeyRegistrationData($this->attestation(), $this->validatedNullableString('name'), $this->sessionContext());
    }
}
