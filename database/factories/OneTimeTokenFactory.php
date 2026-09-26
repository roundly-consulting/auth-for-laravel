<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Database\Factories;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Crypto\Random\Token;

/**
 * @extends Factory<OneTimeToken>
 */
final class OneTimeTokenFactory extends Factory
{
    protected $model = OneTimeToken::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'guard' => 'users',
            'purpose' => OneTimeTokenPurpose::MagicLink,
            'account_type' => 'users',
            'account_id' => 1,
            'email' => 'user'.Token::numeric(6).'@example.com',
            'token_hash' => bin2hex(Token::urlSafe(32)),
            'attempts' => 0,
            'max_attempts' => 1,
            'expires_at' => CarbonImmutable::now()->addMinutes(15),
        ];
    }

    public function forAccount(Model $account, string $guard = 'users'): self
    {
        return $this->state([
            'guard' => $guard,
            'account_type' => $account->getMorphClass(),
            'account_id' => $account->getKey(),
        ]);
    }

    public function expired(): self
    {
        return $this->state(['expires_at' => CarbonImmutable::now()->subSecond()]);
    }
}
