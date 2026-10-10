<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Operator;

/**
 * @extends Factory<Operator>
 */
final class OperatorFactory extends Factory
{
    protected $model = Operator::class;

    public function definition(): array
    {
        return [
            'name' => $this->faker->name(),
            'email' => strtolower($this->faker->unique()->safeEmail()),
            'password' => Hash::make('operator-secret-passphrase'),
        ];
    }
}
