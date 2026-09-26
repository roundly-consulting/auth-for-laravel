<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\LocaleData;
use RoundlyConsulting\Auth\Rules\SupportedLocale;

final class UpdateLocaleRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'locale' => ['nullable', 'string', new SupportedLocale($this->guardConfig())],
            'timezone' => ['nullable', 'string', 'timezone:all'],
        ];
    }

    public function toData(): LocaleData
    {
        return new LocaleData($this->validatedNullableString('locale'), $this->validatedNullableString('timezone'));
    }
}
