<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\RefreshTokenData;

final class RefreshTokenRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return ['refresh_token' => ['required', 'string', 'max:4096']];
    }

    public function toData(): RefreshTokenData
    {
        return new RefreshTokenData($this->validatedString('refresh_token'), $this->sessionContext());
    }
}
