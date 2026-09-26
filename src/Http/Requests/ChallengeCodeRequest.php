<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use RoundlyConsulting\Auth\DataTransferObjects\ChallengeFactorData;
use RoundlyConsulting\Auth\Enums\FactorMethod;

/**
 * `{challenge_token, code, method?}` — a TOTP / recovery code (or an enrolment
 * confirmation code) for a pending challenge.
 */
final class ChallengeCodeRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'challenge_token' => ['required', 'string', 'max:512'],
            'code' => ['required', 'string', 'max:64'],
            'method' => ['nullable', 'string', 'in:totp,recovery_code'],
            'device_name' => ['nullable', 'string', 'max:255'],
        ];
    }

    public function toData(FactorMethod $default = FactorMethod::Totp): ChallengeFactorData
    {
        $method = FactorMethod::tryFrom((string) $this->validatedNullableString('method')) ?? $default;

        return new ChallengeFactorData(
            challengeToken: $this->validatedString('challenge_token'),
            method: $method,
            context: $this->sessionContext(),
            code: $this->validatedString('code'),
        );
    }
}
