<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\PasswordResetData;

final class ResetPasswordRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:512'],
            'password' => ['required', 'string', 'max:1024'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): PasswordResetData
    {
        return new PasswordResetData($this->validatedString('token'), $this->validatedString('password'), $this->sessionContext());
    }
}
