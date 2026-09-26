<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\VerificationData;

/**
 * `{token}` for the link channel, `{token: <code>, email}` for the code channel.
 */
final class VerifyEmailRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:512'],
            'email' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): VerificationData
    {
        return new VerificationData($this->validatedString('token'), $this->validatedNullableString('email'), $this->sessionContext());
    }
}
