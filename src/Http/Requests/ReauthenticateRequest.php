<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;
use RoundlyConsulting\Auth\DataTransferObjects\ReauthenticationData;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Exceptions\FactorNotAllowed;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;

final class ReauthenticateRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'method' => ['required', 'string', 'in:'.implode(',', ReauthenticationMethod::values()->all())],
            'password' => ['required_if:method,password', 'nullable', 'string', 'max:1024'],
            'code' => ['required_if:method,totp,recovery_code,email_otp', 'nullable', 'string', 'max:64'],
            'credential' => ['required_if:method,passkey', 'nullable', 'array'],
        ];
    }

    public function toData(): ReauthenticationData
    {
        $method = ReauthenticationMethod::from($this->validatedString('method'));
        $credential = $this->validatedArray('credential');

        try {
            $assertion = $credential === [] ? null : AuthenticationResponseData::fromArray($credential);
        } catch (PasskeyException $e) {
            throw new FactorNotAllowed($e);
        }

        return new ReauthenticationData(
            method: $method,
            current: CurrentToken::fromRequest($this, $this->guardConfig()),
            context: $this->sessionContext(),
            password: $this->validatedNullableString('password'),
            code: $this->validatedNullableString('code'),
            assertion: $assertion,
        );
    }
}
