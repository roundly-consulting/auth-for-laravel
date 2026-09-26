<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Http\Requests\Concerns\ParsesPasskeyCredentials;

/**
 * `{challenge_token, credential, name?}` — a passkey assertion (second factor) or a
 * registration (forced enrolment) for a pending challenge.
 */
final class ChallengePasskeyRequest extends AuthenticationRequest
{
    use ParsesPasskeyCredentials;

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'challenge_token' => ['required', 'string', 'max:512'],
            'credential' => ['required', 'array'],
            'name' => ['nullable', 'string', 'max:255'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(FactorMethod $method = FactorMethod::Passkey): ChallengeFactorData
    {
        $enrolment = $method === FactorMethod::PasskeyEnrolment;

        return new ChallengeFactorData(
            challengeToken: $this->validatedString('challenge_token'),
            method: $method,
            context: $this->sessionContext(),
            assertion: $enrolment ? null : $this->assertion(),
            attestation: $enrolment ? $this->attestation() : null,
            passkeyName: $this->validatedNullableString('name'),
        );
    }
}
