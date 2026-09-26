<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\EmailChangeData;

final class RequestEmailChangeRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return ['email' => ['required', 'string', 'email', 'max:255']];
    }

    public function toData(): EmailChangeData
    {
        return new EmailChangeData($this->validatedString('email'), $this->sessionContext());
    }
}
