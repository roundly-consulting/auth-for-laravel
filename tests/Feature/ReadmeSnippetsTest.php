<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use RoundlyConsulting\Auth\Actions\Passwords\SetPassword;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Events\PasswordChanged;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Exceptions\ReauthenticationRequired;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Client;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * The README's usage snippets, verbatim where possible — under strict types, like a host.
 */
beforeEach(function (): void {
    Notification::fake();
});

it('runs the facade snippet', function (): void {
    $client = Client::factory()->create();
    $user = User::factory()->create();
    $request = Request::create('/login', 'POST', ['email' => $client->email, 'password' => 'correct-horse-battery'], server: ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_USER_AGENT' => 'Readme/1.0']);
    $this->configureGuard('clients', ['login.password' => true]);

    $guard = Authentication::guard('clients');

    $result = $guard->attempt(
        new PasswordCredentials(identifier: $request->string('email')->toString(), password: $request->string('password')->toString()),
        $guard->contextFrom($request),
    );

    $resource = $result->isAuthenticated()
        ? TokenPairResource::make($result->tokens)
        : ChallengeResource::make($result->challenge);

    Authentication::twoFactor()->status($user);
    Authentication::passwords()->set($user, 'n3w-Passphrase!', InvalidationReason::Security);
    $url = Authentication::invitations()->create(new InvitationData('ada@example.com'))->url;
    Authentication::lock($user, seconds: 3600);

    expect($resource)->toBeInstanceOf(TokenPairResource::class)
        ->and($url)->toContain('#token=')
        ->and($user->fresh()?->isLocked())->toBeTrue();
});

it('keeps invitations off until the guard enables them, as the README notes', function (): void {
    $this->configureGuard('users', ['invitations.enabled' => false]);

    expect(fn () => Authentication::invitations()->create(new InvitationData('ada@example.com')))->toThrow(LoginMethodDisabled::class)
        ->and(config('authentication.defaults.invitations.enabled'))->toBeFalse();
});

it('runs the signed-in snippet: the gate is the caller\'s to run', function (): void {
    $user = User::factory()->create();
    enableTotp($user);
    $this->getJson('/users/auth/me', bearer(issuePair($user, amr: [])))->assertOk();
    $request = request();
    $guard = Authentication::guard('users');

    $current = $guard->tokenFrom($request);

    // A login without a second factor never satisfies the gate of a 2FA account.
    expect(fn () => $guard->reauthentication()->ensureFor(SensitiveAction::DisableTwoFactor, $user, $current))
        ->toThrow(ReauthenticationRequired::class);

    // The facade does not gate: host code that skips ensureFor() vouches for the user.
    $tokens = $guard->twoFactor()->disable($user, $current, $guard->contextFrom($request));

    expect($tokens)->not->toBeNull();
});

it('runs the dependency-injection and action snippets', function (): void {
    $user = User::factory()->create();

    $service = new readonly class(app(AuthenticationManager::class))
    {
        public function __construct(private AuthenticationManager $authentication) {}

        public function __invoke(User $user, string $password): void
        {
            $this->authentication->guard('users')->passwords()->set($user, $password, InvalidationReason::Security);
        }
    };

    $service($user, 'n3w-Passphrase!');
    expect(Hash::check('n3w-Passphrase!', (string) $user->fresh()?->password))->toBeTrue();

    app(SetPassword::class)->execute('users', $user, 'an0ther-Passphrase!', InvalidationReason::Security);
    expect(Hash::check('an0ther-Passphrase!', (string) $user->fresh()?->password))->toBeTrue();
});

it('runs the testing snippets', function (): void {
    Event::fake([PasswordChanged::class]);
    $user = User::factory()->create();

    $this->actingAsAccount($user)->getJson('/users/auth/me')->assertOk();

    Authentication::passwords()->set($user, 'n3w-Passphrase!');

    Event::assertDispatched(PasswordChanged::class);
    $this->assertTokensInvalidated($user, InvalidationReason::PasswordReset);

    // Incident response.
    expect(Authentication::guard('users')->logoutEverywhere($user))->toBeInt();

    Authentication::guard('users')->attempt(new PasswordCredentials($user->email, 'n3w-Passphrase!'), new SessionContext('10.0.0.1', 'Readme/1.0'));
    $this->assertLoginActivity('users', ActivityType::PasswordLogin, ActivityOutcome::Succeeded);
});
