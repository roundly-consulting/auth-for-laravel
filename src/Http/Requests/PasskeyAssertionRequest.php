<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\Http\Requests\Concerns\ParsesPasskeyCredentials;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;

final class PasskeyAssertionRequest extends AuthenticationRequest
{
    use ParsesPasskeyCredentials;

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'credential' => ['required', 'array'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): AuthenticationResponseData
    {
        return $this->assertion();
    }
}
