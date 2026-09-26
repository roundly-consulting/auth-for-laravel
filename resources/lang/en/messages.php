<?php

declare(strict_types=1);

return [
    'errors' => [
        'invalid_credentials' => 'These credentials do not match our records.',
        'invalid_token' => 'This link is invalid or has expired.',
        'invalid_code' => 'This code is invalid or has expired.',
        'challenge_invalid' => 'This sign-in attempt has expired. Please sign in again.',
        'factor_failed' => 'The verification failed. Please try again.',
        'factor_not_allowed' => 'This verification method cannot be used here.',
        'invalid_invitation' => 'This invitation is invalid or has expired.',
        'refresh_invalid' => 'Your session has expired. Please sign in again.',
        'enrolment_required' => 'This account must set up an additional sign-in factor, which cannot be done here.',
        'too_many_attempts' => 'Too many attempts. Please try again later.',
        'account_disabled' => 'This account has been disabled.',
        'account_locked' => 'This account is temporarily locked.',
        'email_not_verified' => 'Please verify your email address first.',
        'method_disabled' => 'Not found.',
        'registration_closed' => 'Registration is closed.',
        'invitation_required' => 'Registration requires an invitation.',
        'reauthentication_required' => 'Please confirm your identity to continue.',
        'two_factor_required' => 'Two-factor authentication is required and cannot be disabled.',
        'last_credential' => 'This is your last way to sign in and cannot be removed.',
        'two_factor_already_enabled' => 'Two-factor authentication is already enabled.',
        'two_factor_not_enabled' => 'Two-factor authentication is not enabled.',
        'passkey_registration_failed' => 'The passkey could not be registered.',
        'not_found' => 'Not found.',
        'login_denied' => 'This sign-in was blocked for your security.',
        'password_check_unavailable' => 'The password could not be checked right now. Please try again.',
        'misconfigured' => 'Authentication is not available right now.',
    ],

    'two_factor' => [
        'qr_title' => 'Two-factor authentication setup code',
    ],
];
