<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use SensitiveParameter;

final readonly class RecoveryCodesData
{
    /**
     * @param  list<string>  $codes
     */
    public function __construct(
        #[SensitiveParameter] public array $codes,
        public ?TokenPair $tokens = null,
    ) {}
}
