<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Passwords\SetPassword;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * The README's usage snippets, verbatim where possible — under strict types, like a host.
 */
beforeEach(function (): void {
    Notification::fake();
});

it('runs the facade snippet', function (): void {
    $user = User::factory()->create();
    $request = Request::create('/login', 'POST', ['email' => $user->email, 'password' => 'correct-horse-battery'], server: ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_USER_AGENT' => 'Readme/1.0']);

    $result = Authentication::guard('users')->attempt(
        new PasswordCredentials(identifier: $request->string('email')->toString(), password: $request->string('password')->toString()),
        SessionContext::fromRequest($request),
    );

    $resource = $result->isAuthenticated()
        ? TokenPairResource::make($result->tokens)
        : ChallengeResource::make($result->challenge);

    expect($resource)->toBeInstanceOf(TokenPairResource::class);
});

it('runs the action and testing-helper snippets', function (): void {
    $user = User::factory()->create();

    $this->actingAsAccount($user)->getJson('/users/auth/me')->assertOk();

    // An admin sets a password: every session of the account ends.
    app(SetPassword::class)->execute('users', $user, 'n3w-Passphrase!', InvalidationReason::Security);

    $this->assertTokensInvalidated($user, InvalidationReason::Security);

    // Incident response.
    expect(Authentication::guard('users')->logoutEverywhere($user))->toBeInt();

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'n3w-Passphrase!'), new SessionContext('10.0.0.1', 'Readme/1.0'));
    $this->assertLoginActivity('users', ActivityType::PasswordLogin, ActivityOutcome::Succeeded);
});
