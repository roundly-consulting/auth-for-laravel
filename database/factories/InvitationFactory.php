<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Database\Factories;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\Factory;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Crypto\Random\Token;

/**
 * @extends Factory<Invitation>
 */
final class InvitationFactory extends Factory
{
    protected $model = Invitation::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'guard' => 'users',
            'email' => 'invitee'.Token::numeric(6).'@example.com',
            'token_hash' => null,
            'payload' => [],
            'send_count' => 0,
            'expires_at' => CarbonImmutable::now()->addDays(7),
        ];
    }

    public function accepted(): self
    {
        return $this->state(['accepted_at' => CarbonImmutable::now()]);
    }

    public function revoked(): self
    {
        return $this->state(['revoked_at' => CarbonImmutable::now()]);
    }

    public function expired(): self
    {
        return $this->state(['expires_at' => CarbonImmutable::now()->subSecond()]);
    }
}
