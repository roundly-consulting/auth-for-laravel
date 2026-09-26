<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\CodeData;

final class CodeRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return ['code' => ['required', 'string', 'max:64']];
    }

    public function toData(): CodeData
    {
        return new CodeData($this->validatedString('code'), $this->sessionContext());
    }
}
