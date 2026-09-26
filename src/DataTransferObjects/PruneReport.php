<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

final readonly class PruneReport
{
    public function __construct(
        public int $challenges,
        public int $oneTimeTokens,
        public int $invitations,
        public int $activities,
    ) {}

    public function total(): int
    {
        return $this->challenges + $this->oneTimeTokens + $this->invitations + $this->activities;
    }
}
