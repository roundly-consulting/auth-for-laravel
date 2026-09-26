<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Database\Factories;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Crypto\Random\Token;

/**
 * @extends Factory<LoginChallenge>
 */
final class LoginChallengeFactory extends Factory
{
    protected $model = LoginChallenge::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'guard' => 'users',
            'account_type' => 'users',
            'account_id' => 1,
            'token_hash' => bin2hex(Token::urlSafe(32)),
            'method' => LoginMethod::Password,
            'required_steps' => [[
                'step' => ChallengeStep::SecondFactor->value,
                'methods' => [FactorMethod::Totp->value, FactorMethod::RecoveryCode->value],
            ]],
            'completed_steps' => [],
            'context' => ['amr' => ['pwd'], 'auth_time' => CarbonImmutable::now()->getTimestamp(), 'token_version' => 0],
            'attempts' => 0,
            'max_attempts' => 5,
            'version' => 0,
            'expires_at' => CarbonImmutable::now()->addMinutes(5),
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
