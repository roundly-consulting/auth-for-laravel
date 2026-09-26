<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\PasskeyNameData;

final class RenamePasskeyRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return ['name' => ['required', 'string', 'max:255']];
    }

    public function toData(): PasskeyNameData
    {
        return new PasskeyNameData($this->validatedString('name'));
    }
}
