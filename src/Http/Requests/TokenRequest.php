<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\TokenData;

/**
 * A request carrying an emailed secret in its BODY (never the path or query string).
 */
final class TokenRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:512'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): TokenData
    {
        return new TokenData($this->validatedString('token'), $this->sessionContext());
    }
}
