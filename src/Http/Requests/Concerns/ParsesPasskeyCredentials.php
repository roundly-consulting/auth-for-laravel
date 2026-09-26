<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests\Concerns;

use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;

/**
 * Decodes the browser's `credential` payload (base64url members) through passkeys'
 * strict parsers; a malformed payload is a plain validation error.
 */
trait ParsesPasskeyCredentials
{
    protected function assertion(): AuthenticationResponseData
    {
        try {
            return AuthenticationResponseData::fromArray($this->credentialPayload());
        } catch (PasskeyException) {
            throw ValidationException::withMessages(['credential' => __('authentication::messages.errors.factor_failed')]);
        }
    }

    protected function attestation(): RegistrationResponseData
    {
        try {
            return RegistrationResponseData::fromArray($this->credentialPayload());
        } catch (PasskeyException) {
            throw ValidationException::withMessages(['credential' => __('authentication::messages.errors.passkey_registration_failed')]);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function credentialPayload(): array
    {
        $credential = $this->validated('credential');

        return is_array($credential) ? $credential : [];
    }
}
