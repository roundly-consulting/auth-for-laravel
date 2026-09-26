<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use SensitiveParameter;

/**
 * A factor submitted to a pending login challenge.
 */
final readonly class ChallengeFactorData
{
    public function __construct(
        #[SensitiveParameter] public string $challengeToken,
        public FactorMethod $method,
        public SessionContext $context,
        #[SensitiveParameter] public ?string $code = null,
        public ?AuthenticationResponseData $assertion = null,
        public ?RegistrationResponseData $attestation = null,
        public ?string $passkeyName = null,
    ) {}
}
