<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

final readonly class InvitationData
{
    /**
     * @param  array<string, mixed>  $payload  host role/meta JSON, surfaced on acceptance
     * @param  bool|null  $replacePending  revoke an open invitation to the same address; null = the guard's `invitations.replace_pending`
     */
    public function __construct(
        public string $email,
        public array $payload = [],
        public ?Model $invitedBy = null,
        public ?string $locale = null,
        public ?int $ttl = null,
        public bool $send = true,
        public ?bool $replacePending = null,
    ) {}
}
