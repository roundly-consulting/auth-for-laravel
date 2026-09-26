<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Contracts\ProvidesRegistrationRules;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Rules\PasswordPolicy;
use SensitiveParameter;

/**
 * Validates a new account's email, password and the host's extra attributes, and
 * returns ONLY the attributes the host's rules name — nothing unvalidated ever reaches
 * the account creator (the models use `$guarded = []`). Dotted and wildcard rules
 * (`profile.city`, `tags.*`) keep exactly the nested values they validated.
 */
final readonly class RegistrationValidator
{
    public function __construct(private Container $container) {}

    /**
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed> the allow-listed, validated attributes
     *
     * @throws ValidationException
     */
    public function validate(GuardConfig $guard, string $email, #[SensitiveParameter] ?string $password, array $attributes): array
    {
        $hostRules = $this->hostRules($guard);

        $validator = Validator::make(
            ['email' => $email, 'password' => $password, 'attributes' => $attributes],
            [
                'email' => ['required', 'string', 'email', 'max:255'],
                'password' => [
                    $guard->registrationRequiresPassword() ? 'required' : 'nullable',
                    'string',
                    new PasswordPolicy($guard, $email),
                ],
                ...array_combine(
                    array_map(static fn (string $key): string => 'attributes.'.$key, array_keys($hostRules)),
                    array_values($hostRules),
                ),
            ],
        );

        // Only ruled keys come back from validated() — top-level, dotted or wildcard;
        // with no host rules there is no `attributes` key at all.
        $validated = $validator->validate();

        return is_array($validated['attributes'] ?? null) ? $validated['attributes'] : [];
    }

    /**
     * @return array<string, mixed>
     */
    private function hostRules(GuardConfig $guard): array
    {
        $class = $guard->registrationRules();
        $provider = $class === null ? null : $this->container->make($class);

        return $provider instanceof ProvidesRegistrationRules ? $provider->rules($guard) : [];
    }
}
