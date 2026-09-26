<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * @extends Factory<User>
 */
final class UserFactory extends Factory
{
    protected $model = User::class;

    public function definition(): array
    {
        return [
            'name' => $this->faker->name(),
            'email' => strtolower($this->faker->unique()->safeEmail()),
            'email_verified_at' => now(),
            'password' => Hash::make('correct-horse-battery'),
        ];
    }

    public function unverified(): self
    {
        return $this->state(['email_verified_at' => null]);
    }

    public function passwordless(): self
    {
        return $this->state(['password' => null]);
    }

    public function disabled(): self
    {
        return $this->state(['disabled_at' => now(), 'disabled_reason' => 'test']);
    }
}
