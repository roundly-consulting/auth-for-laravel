<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Models\LoginActivity;

/**
 * @extends Factory<LoginActivity>
 */
final class LoginActivityFactory extends Factory
{
    protected $model = LoginActivity::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'guard' => 'users',
            'type' => ActivityType::PasswordLogin,
            'outcome' => ActivityOutcome::Succeeded,
            'method' => 'password',
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Pest',
            'is_new_device' => false,
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
}
