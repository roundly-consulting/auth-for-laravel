<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\AcceptInvitationData;

final class AcceptInvitationRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:512'],
            'password' => ['nullable', 'string', 'max:1024'],
            'email' => ['nullable', 'string', 'max:255'],
            'attributes' => ['nullable', 'array'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(): AcceptInvitationData
    {
        return new AcceptInvitationData(
            token: $this->validatedString('token'),
            password: $this->validatedNullableString('password'),
            context: $this->sessionContext(),
            attributes: $this->validatedArray('attributes'),
            email: $this->validatedNullableString('email'),
        );
    }
}
