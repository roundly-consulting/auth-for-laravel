<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Http\Requests\AuthenticationRequest;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Testing\Arch\ArchPresets;

ArchPresets::strictTypes('RoundlyConsulting\Auth');

/**
 * Exempt: the four swappable models (pinned non-final below), the misconfiguration base
 * GuardNotConfigured extends, the form-request base, and the two documented extension
 * namespaces (notifications and resources are swapped per guard through config).
 */
ArchPresets::finalByDefault('RoundlyConsulting\Auth', [
    LoginChallenge::class,
    OneTimeToken::class,
    Invitation::class,
    LoginActivity::class,
    AuthenticationMisconfigured::class,
    AuthenticationRequest::class,
    'RoundlyConsulting\Auth\Notifications',
    'RoundlyConsulting\Auth\Http\Resources',
]);

ArchPresets::swappableModelsAreNotFinal([
    LoginChallenge::class => 'authentication.models.challenge',
    OneTimeToken::class => 'authentication.models.one_time_token',
    Invitation::class => 'authentication.models.invitation',
    LoginActivity::class => 'authentication.models.login_activity',
]);

ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\Auth');

ArchPresets::modelsResolveThroughSeam(__DIR__.'/../../src', 'Support', [
    'authentication.models.challenge',
    'authentication.models.one_time_token',
    'authentication.models.invitation',
    'authentication.models.login_activity',
]);

// 4 create migrations + the users-table stub.
ArchPresets::morphColumnsUseTheSeam(__DIR__.'/../../database/migrations');

ArchPresets::runtimeRequireIsWhitelisted(__DIR__.'/../../composer.json');

ArchPresets::noDebuggingLeftovers();
