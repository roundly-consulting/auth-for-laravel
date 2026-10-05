<?php

declare(strict_types=1);

return [
    'code_line' => 'Your code: :code',
    'expiry' => '{1} This expires in :minutes minute.|[0,*] This expires in :minutes minutes.',

    'magic_link' => [
        'subject' => 'Your sign-in link for :app',
        'intro' => 'Use the button below to sign in to :app.',
        'action' => 'Sign in',
        'outro' => 'If you did not request this, you can ignore this email.',
    ],
    'email_otp' => [
        'subject' => 'Your sign-in code for :app',
        'intro' => 'Use this code to continue signing in to :app.',
        'action' => 'Continue',
        'outro' => 'If you did not request this, you can ignore this email.',
    ],
    'verify_email' => [
        'subject' => 'Verify your email address',
        'intro' => 'Please confirm that this is your email address.',
        'action' => 'Verify email address',
        'outro' => 'If you did not create an account, no further action is required.',
    ],
    'reset_password' => [
        'subject' => 'Reset your :app password',
        'intro' => 'We received a request to reset the password of your account.',
        'action' => 'Reset password',
        'outro' => 'If you did not request a password reset, no further action is required.',
    ],
    'password_changed' => [
        'subject' => 'Your :app password was changed',
        'intro' => 'The password of your account was just changed.',
        'action' => 'Review your account',
        'outro' => 'If this was not you, reset your password immediately.',
    ],
    'email_change_confirmation' => [
        'subject' => 'Confirm your new email address',
        'intro' => 'Please confirm that you want to use this address for your :app account.',
        'action' => 'Confirm email address',
        'outro' => 'If you did not request this change, you can ignore this email.',
    ],
    'email_change_requested' => [
        'subject' => 'An email change was requested for your :app account',
        'intro' => 'Someone asked to change the email address of your account to :new_email.',
        'action' => 'Review your account',
        'outro' => 'If this was not you, change your password and contact support.',
    ],
    'email_changed' => [
        'subject' => 'Your :app email address was changed',
        'intro' => 'The email address of your account was changed to :new_email.',
        'action' => 'Review your account',
        'outro' => 'If this was not you, contact support immediately.',
    ],
    'account_exists' => [
        'subject' => 'You already have a :app account',
        'intro' => 'Someone tried to use this email address for a new account or email change, but an account already uses it.',
        'action' => 'Sign in',
        'outro' => 'If this was not you, you can ignore this email.',
    ],
    'invitation' => [
        'subject' => 'You are invited to :app',
        'intro' => 'You have been invited to create an account.',
        'action' => 'Accept invitation',
        'outro' => 'If you did not expect this invitation, you can ignore this email.',
    ],
    'new_device' => [
        'subject' => 'New sign-in to your :app account',
        'intro' => 'Your account was just accessed from a new device (:ip, :user_agent) at :time.',
        'action' => 'Review your sessions',
        'outro' => 'If this was not you, sign out everywhere and change your password.',
    ],
    'two_factor_enabled' => [
        'subject' => 'Two-factor authentication enabled',
        'intro' => 'Two-factor authentication was enabled on your account.',
        'action' => 'Review your account',
        'outro' => 'If this was not you, contact support immediately.',
    ],
    'two_factor_disabled' => [
        'subject' => 'Two-factor authentication disabled',
        'intro' => 'Two-factor authentication was disabled on your account.',
        'action' => 'Review your account',
        'outro' => 'If this was not you, contact support immediately.',
    ],
    'recovery_code_used' => [
        'subject' => 'A recovery code was used',
        'intro' => 'A recovery code was just used to sign in to your account. You have :remaining left.',
        'action' => 'Review your account',
        'outro' => 'If this was not you, contact support immediately.',
    ],
    'passkey_added' => [
        'subject' => 'A passkey was added to your account',
        'intro' => 'A new passkey can now be used to sign in to your account.',
        'action' => 'Review your passkeys',
        'outro' => 'If this was not you, contact support immediately.',
    ],
    'passkey_removed' => [
        'subject' => 'A passkey was removed from your account',
        'intro' => 'A passkey was removed from your account.',
        'action' => 'Review your passkeys',
        'outro' => 'If this was not you, contact support immediately.',
    ],
    'account_locked' => [
        'subject' => 'Your :app account was locked',
        'intro' => 'Your account was temporarily locked after too many failed sign-in attempts.',
        'action' => 'Reset your password',
        'outro' => 'If these attempts were not yours, consider changing your password.',
    ],
    'refresh_token_reuse' => [
        'subject' => 'Suspicious activity on your :app account',
        'intro' => 'We noticed suspicious activity on your account (:reason) and signed the affected session out.',
        'action' => 'Review your sessions',
        'outro' => 'If this was not you, sign out everywhere and change your password.',
        'reasons' => [
            'token_reuse' => 'a reused session token',
        ],
    ],
    'sign_in_blocked' => [
        'subject' => 'We blocked a sign-in to your :app account',
        'intro' => 'We blocked an attempt to sign in to your account because it looked suspicious. Nobody was signed in.',
        'action' => 'Review your sessions',
        'outro' => 'If this was you, try again later or from a device you usually use. If it was not you, change your password.',
    ],
    'unusual_sign_in' => [
        'subject' => 'Unusual sign-in to your :app account',
        'intro' => 'Someone just signed in to your account in a way that looked unusual.',
        'action' => 'Review your sessions',
        'outro' => 'If this was you, no action is needed. If it was not you, sign out everywhere and change your password right away.',
    ],
];
