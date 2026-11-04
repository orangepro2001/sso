<?php

namespace Database\Factories;

use App\Models\OauthClient;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<OauthClient>
 */
class OauthClientFactory extends Factory
{
    protected $model = OauthClient::class;

    public function definition(): array
    {
        return [
            'client_id' => OauthClient::generateClientId(),
            'name' => fake()->company(),
            'type' => OauthClient::TYPE_PUBLIC,
            'secret_hash' => null,
            'redirect_uris' => ['https://client.example/callback'],
            'allowed_scopes' => ['openid', 'profile', 'email', 'offline_access', 'db:read'],
            'active' => true,
        ];
    }

    public function confidential(?string $secret = 'client-secret-1'): static
    {
        return $this->state(fn () => [
            'type' => OauthClient::TYPE_CONFIDENTIAL,
            'secret_hash' => $secret === null ? null : password_hash($secret, PASSWORD_DEFAULT),
        ]);
    }
}
