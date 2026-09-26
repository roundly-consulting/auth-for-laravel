<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\EmailRequestData;

/**
 * A guest request naming an address (magic link, email code, password reset,
 * verification resend). Answered identically whether or not the address is known.
 */
final class EmailRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return ['email' => ['required', 'string', 'email', 'max:255']];
    }

    public function toData(): EmailRequestData
    {
        return new EmailRequestData($this->validatedString('email'), $this->sessionContext());
    }
}
