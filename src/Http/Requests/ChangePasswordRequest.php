<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\ChangePasswordData;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;

final class ChangePasswordRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'current_password' => ['nullable', 'string', 'max:1024'],
            'password' => ['required', 'string', 'max:1024'],
        ];
    }

    public function toData(): ChangePasswordData
    {
        return new ChangePasswordData(
            currentPassword: $this->validatedNullableString('current_password'),
            newPassword: $this->validatedString('password'),
            current: CurrentToken::fromRequest($this, $this->guardConfig()),
            context: $this->sessionContext(),
        );
    }
}
