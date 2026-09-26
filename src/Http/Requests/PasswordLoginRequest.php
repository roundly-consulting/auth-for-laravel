<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;

final class PasswordLoginRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'identifier' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'max:1024'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): PasswordCredentials
    {
        return new PasswordCredentials($this->validatedString('identifier'), $this->validatedString('password'));
    }
}
