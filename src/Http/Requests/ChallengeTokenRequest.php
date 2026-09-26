<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\TokenData;

final class ChallengeTokenRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return ['challenge_token' => ['required', 'string', 'max:512']];
    }

    public function toData(): TokenData
    {
        return new TokenData($this->validatedString('challenge_token'), $this->sessionContext());
    }
}
