<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use SensitiveParameter;

final readonly class ReauthenticationData
{
    public function __construct(
        public ReauthenticationMethod $method,
        public CurrentToken $current,
        public SessionContext $context,
        #[SensitiveParameter] public ?string $password = null,
        #[SensitiveParameter] public ?string $code = null,
        public ?AuthenticationResponseData $assertion = null,
    ) {}
}
