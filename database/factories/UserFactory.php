<?php

namespace Database\Factories;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;

/**
 * @extends Factory<User>
 */
class UserFactory extends Factory
{
    protected $model = User::class;

    public function definition(): array
    {
        return [
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'password' => Hash::make('password-password'),
            'status' => User::STATUS_ACTIVE,
        ];
    }

    public function disabled(): static
    {
        return $this->state(fn () => ['status' => User::STATUS_DISABLED]);
    }
}
