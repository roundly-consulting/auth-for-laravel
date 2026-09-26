<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Support\AboutSection;

it('renders the about section without leaking secrets', function (): void {
    config()->set('authentication.hash_key', 'super-secret-hash-key-value');

    expect('authentication')->toLeakNoSecrets(
        secrets: ['super-secret-hash-key-value', config('app.key')],
        mustRender: ['Guards', 'Hash key', 'Login methods', 'Breach check', 'Access-token revoker'],
    );
});

it('reports the wiring', function (): void {
    expect(AboutSection::data())
        ->toMatchArray([
            'Guards' => 'users, clients',
            'Default guard' => 'users',
            'Hash key' => 'DERIVED',
            'Access-token revoker' => 'BOUND',
            '2FA' => 'optional',
            'Routes' => 'ON',
            'Audience' => 'SET',
        ]);
});

it('says so when the default guard is misconfigured', function (): void {
    $this->configureGuard('users', ['model' => null]);

    expect(AboutSection::data())->toHaveKey('Status');
});
