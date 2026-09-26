<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\EmailCodeData;

final class EmailCodeRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'email' => ['required', 'string', 'email', 'max:255'],
            'code' => ['required', 'string', 'max:16'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): EmailCodeData
    {
        return new EmailCodeData($this->validatedString('email'), $this->validatedString('code'), $this->sessionContext());
    }
}
