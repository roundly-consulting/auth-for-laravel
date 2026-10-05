<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Actions\Registration\CreateAccount;
use RoundlyConsulting\Auth\Http\Resources\AccountResource;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\Auth\Notifications;
use RoundlyConsulting\Auth\Support\DefaultClaimsResolver;

return [

    /*
    |--------------------------------------------------------------------------
    | Global settings
    |--------------------------------------------------------------------------
    |
    | Top-level keys apply to every guard. Everything under `defaults` is PER GUARD
    | and may be overridden in `guards.<name>` — associative arrays merge
    | recursively, lists (e.g. `identifier.columns`) replace wholesale.
    |
    */

    // Guard used when Authentication::guard() is called without a name.
    'default' => env('AUTHENTICATION_GUARD', 'users'),

    // PK type shared by every guard model; drives every morph id column. bigint|uuid|ulid.
    // Must equal passkeys.key_type and refresh-tokens.key_type (the morph columns are shared).
    'key_type' => env('AUTHENTICATION_KEY_TYPE', 'bigint'),

    // HMAC key for one-time secrets, challenge tokens, fingerprints and throttle keys.
    // Null → derived from APP_KEY. Rotating it invalidates every outstanding link/code/challenge.
    'hash_key' => env('AUTHENTICATION_HASH_KEY'),

    'tables' => [
        'challenges' => env('AUTHENTICATION_CHALLENGES_TABLE', 'auth_login_challenges'),
        'one_time_tokens' => env('AUTHENTICATION_ONE_TIME_TOKENS_TABLE', 'auth_one_time_tokens'),
        'invitations' => env('AUTHENTICATION_INVITATIONS_TABLE', 'auth_invitations'),
        'login_activities' => env('AUTHENTICATION_LOGIN_ACTIVITIES_TABLE', 'auth_login_activities'),
    ],

    // Swappable models (must extend the packaged ones).
    'models' => [
        'challenge' => LoginChallenge::class,
        'one_time_token' => OneTimeToken::class,
        'invitation' => Invitation::class,
        'login_activity' => LoginActivity::class,
    ],

    // Column names on every guard (account) table.
    'columns' => [
        'token_version' => 'token_version',
        'locale' => 'locale',
        'timezone' => 'timezone',
        'password' => 'password',
        'password_changed_at' => 'password_changed_at',
        'email_verified_at' => 'email_verified_at',
        'last_login_at' => 'last_login_at',
        'disabled_at' => 'disabled_at',
        'disabled_reason' => 'disabled_reason',
        'locked_until' => 'locked_until',
        'failed_login_count' => 'failed_login_count',
    ],

    // Cache store for re-authentication markers (null = default cache store).
    'reauthentication_store' => env('AUTHENTICATION_REAUTH_STORE'),

    'defaults' => [
        'model' => null,            // REQUIRED per guard: class-string<Model&Account>
        'laravel_guard' => null,    // auth.guards key using the `jwt` driver; null → guard name

        'identifier' => [
            'columns' => ['email'],             // columns accepted as login identifier (list: replaced, not merged)
            'email_column' => 'email',
            'normalize' => 'lowercase',         // lowercase|none
            'case_insensitive_lookup' => false, // lower(col) = ? for legacy mixed-case data
        ],

        'login' => [
            'password' => env('AUTHENTICATION_LOGIN_PASSWORD', true),
            'magic_link' => env('AUTHENTICATION_LOGIN_MAGIC_LINK', false),
            'email_otp' => env('AUTHENTICATION_LOGIN_EMAIL_OTP', false),
            'passkey' => env('AUTHENTICATION_LOGIN_PASSKEY', false),  // passwordless
            'reveal_account_state' => true,  // disabled/unverified codes only after a verified first factor
        ],

        'challenge' => [
            'ttl' => 300,
            'enrolment_ttl' => 900,
            'max_attempts' => 5,
            'allow_enrolment' => true,
            'enrolment_requires_verified_email' => true,
            'bind' => ['user_agent' => true, 'ip' => false, 'device_header' => true],
            'max_active_per_account' => 3,   // older active challenges are superseded
        ],

        'two_factor' => [
            'mode' => env('AUTHENTICATION_TWO_FACTOR', 'optional'),  // off|optional|required
            'after_email_login' => true,          // magic link / email OTP / invitation also need the 2nd factor
            'required_with_passkey' => false,     // passkey primary still forces TOTP enrolment when mode=required
            'passkey_satisfies_required' => true, // a passkey second factor satisfies mode=required (false ⇒ TOTP also required)
            'issuer' => null,                     // otpauth issuer for this guard; null → two-factor.issuer / app.name
            'qr' => ['enabled' => true, 'size' => 240],
        ],

        'passkeys' => [
            'mode' => env('AUTHENTICATION_PASSKEYS', 'optional'),    // off|optional|required
            'second_factor' => 'allowed',        // off|allowed|required_when_enrolled|required
            'satisfies_mfa' => true,             // a UV passkey login needs no further factor
        ],

        'tokens' => [
            'access_ttl' => null,                // seconds; null → jwt.ttl
            'refresh_ttl' => 2_592_000,          // sliding, 30 days
            'refresh_absolute_ttl' => 7_776_000, // 90 days; 0 = no cap
            'claims_resolver' => DefaultClaimsResolver::class,
            'include_email' => true,
        ],

        'sessions' => [
            'max_active' => null,                // int|null — oldest sessions revoked above the cap
        ],

        'invalidation' => [                      // none|others|all  (account_disabled is always all)
            'password_changed' => 'others',
            'password_reset' => 'all',
            'email_changed' => 'others',
            'two_factor_changed' => 'others',
            'passkey_changed' => 'none',
        ],

        'registration' => [
            'mode' => env('AUTHENTICATION_REGISTRATION', 'closed'),  // open|invite_only|closed
            'require_password' => true,          // when login.password is on
            'login_after' => true,
            'rules' => null,                     // class-string<ProvidesRegistrationRules>|null
            'creator' => CreateAccount::class,   // class-string<CreatesAccounts>
        ],

        'invitations' => [
            'enabled' => false,
            'ttl' => 604_800,                    // 7 days
            'lock_email' => true,
            'replace_pending' => true,
            'allow_existing_email' => false,
            'resend_cooldown' => 60,
            'max_sends' => 5,
            'preview_payload_keys' => [],        // payload keys exposed by the preview endpoint
            'ability' => 'authentication.invitations.manage',  // Gate ability for management routes
        ],

        'verification' => [
            'mode' => env('AUTHENTICATION_VERIFICATION', 'optional'), // off|optional|required_for_actions|required_for_login
            'channel' => 'link',                 // link|code
            'ttl' => 86_400,
            'code_length' => 6,
            'max_attempts' => 5,
            'resend_decay' => 60,
            'verify_on_email_login' => true,
        ],

        'email_change' => [
            'enabled' => true,
            'ttl' => 3_600,
            'notify_old' => true,
            'require_reauthentication' => true,  // false switches the gate off; else reauthentication.required_for decides (change_email)
        ],

        'magic_link' => ['ttl' => 900, 'same_device' => false],

        'email_otp' => ['ttl' => 600, 'length' => 6, 'max_attempts' => 5],

        'passwords' => [
            'reset' => ['enabled' => true, 'ttl' => 3_600, 'login_after' => false],
            'change' => ['enabled' => true],
            'rehash_on_login' => true,
            'policy' => [
                'min' => 10,
                'max' => 128,                    // bytes capped at 72 automatically under bcrypt
                'letters' => false,
                'mixed_case' => false,
                'numbers' => false,
                'symbols' => false,
                'not_identifier' => true,
                'uncompromised' => [
                    'enabled' => env('AUTHENTICATION_PASSWORD_BREACH_CHECK', false),
                    'threshold' => 0,
                    'timeout' => 3,
                    'fail_closed' => false,
                ],
            ],
        ],

        'throttle' => [                          // max attempts / decay seconds
            'login' => ['max' => 5, 'decay' => 60],                 // identifier + IP
            'login_ip' => ['max' => 50, 'decay' => 600],            // IP, any identifier
            'login_account' => ['max' => 20, 'decay' => 3_600],     // identifier, any IP
            'email_request' => ['max' => 3, 'decay' => 600],        // link/OTP/reset/resend per identifier+IP
            'email_request_ip' => ['max' => 20, 'decay' => 600],
            'email_request_account' => ['max' => 10, 'decay' => 3_600],   // identifier, any IP (mail-bombing / OTP budget cap)
            'refresh' => ['max' => 30, 'decay' => 60],              // per IP
            'registration' => ['max' => 5, 'decay' => 3_600],       // per IP
            'verification' => ['max' => 5, 'decay' => 600],         // verify attempts per identifier+IP
            'reauthentication' => ['max' => 5, 'decay' => 300],     // per session
        ],

        'lockout' => [
            'enabled' => false,
            'threshold' => 10,
            'duration' => 900,
            'reset_unlocks' => true,
        ],

        'reauthentication' => [
            'timeout' => 900,
            'methods' => ['password', 'totp', 'recovery_code', 'passkey', 'email_otp'],
            'require_second_factor_when_enrolled' => true,  // 2FA/passkey accounts must reauth with totp|recovery_code|passkey
            'fresh_login_counts' => true,                   // auth_time within timeout satisfies the check
            // Sensitive actions gated by a recent reauthentication; drop an entry to drop its gate
            // (list: replaced, not merged). set_password = an account without a password setting one.
            'required_for' => ['enable_two_factor', 'disable_two_factor', 'regenerate_recovery_codes',
                'register_passkey', 'remove_passkey', 'change_email', 'set_password', 'logout_everywhere'],
        ],

        'activity' => [
            'enabled' => true,
            'store_identifier' => 'plain',       // plain|hash|none
            'retention_days' => 90,
            'new_device' => [
                'enabled' => true,
                'header' => 'X-Device-Id',
                'skip_first_login' => true,
            ],
        ],

        'risk' => [
            'assessor' => null,                  // class-string<AssessesLoginRisk>|null
            'reactions' => ['elevated' => 'notify', 'high' => 'require_second_factor'],  // allow|notify|require_second_factor|deny
            'deny_response' => 'uniform',        // uniform|explicit
        ],

        'locale' => [
            'header' => 'X-Locale',
            'supported' => null,                 // list<string>|null → [app.locale]
            'store_on_registration' => true,
            'fill_on_login' => true,
            'timezone' => true,
        ],

        'notifications' => [
            'delivery' => env('AUTHENTICATION_NOTIFICATION_DELIVERY', 'after_response'), // sync|after_response|queue
            'connection' => env('AUTHENTICATION_NOTIFICATION_CONNECTION'),
            'queue' => env('AUTHENTICATION_NOTIFICATION_QUEUE'),
            'classes' => [                       // null disables an optional notification
                'magic_link' => Notifications\MagicLinkNotification::class,
                'email_otp' => Notifications\EmailOtpNotification::class,
                'verify_email' => Notifications\VerifyEmailNotification::class,
                'reset_password' => Notifications\ResetPasswordNotification::class,
                'password_changed' => Notifications\PasswordChangedNotification::class,
                'email_change_confirmation' => Notifications\ConfirmEmailChangeNotification::class,
                'email_change_requested' => Notifications\EmailChangeRequestedNotification::class,
                'email_changed' => Notifications\EmailChangedNotification::class,
                'account_exists' => Notifications\AccountExistsNotification::class,
                'invitation' => Notifications\InvitationNotification::class,
                'new_device' => Notifications\NewDeviceLoginNotification::class,
                'two_factor_enabled' => Notifications\TwoFactorEnabledNotification::class,
                'two_factor_disabled' => Notifications\TwoFactorDisabledNotification::class,
                'recovery_code_used' => Notifications\RecoveryCodeUsedNotification::class,
                'passkey_added' => Notifications\PasskeyAddedNotification::class,
                'passkey_removed' => Notifications\PasskeyRemovedNotification::class,
                'account_locked' => Notifications\AccountLockedNotification::class,
                'refresh_token_reuse' => Notifications\SuspiciousSessionNotification::class,
                'sign_in_blocked' => Notifications\SignInBlockedNotification::class,   // risk reaction deny
                'unusual_sign_in' => Notifications\UnusualSignInNotification::class,   // risk reaction notify
            ],
            // Base URL of this guard's frontend; null → app.url. Substituted for {frontend}.
            'frontend_url' => env('AUTHENTICATION_FRONTEND_URL'),
            // Frontend URL templates: {token} {email} {guard} {frontend} {app} placeholders, rawurlencoded.
            // Secrets go in the FRAGMENT by default: never sent to the frontend server, never in Referer.
            'urls' => [
                'magic_link' => env('AUTHENTICATION_URL_MAGIC_LINK', '{frontend}/auth/magic-link?guard={guard}#token={token}'),
                'verify_email' => env('AUTHENTICATION_URL_VERIFY_EMAIL', '{frontend}/auth/verify-email?guard={guard}#token={token}'),
                'reset_password' => env('AUTHENTICATION_URL_RESET_PASSWORD', '{frontend}/auth/reset-password?guard={guard}#token={token}'),
                'confirm_email_change' => env('AUTHENTICATION_URL_CONFIRM_EMAIL_CHANGE', '{frontend}/auth/confirm-email?guard={guard}#token={token}'),
                'invitation' => env('AUTHENTICATION_URL_INVITATION', '{frontend}/auth/invitation?guard={guard}#token={token}'),
            ],
        ],

        'routes' => [
            'enabled' => false,                  // opt-in; or call Authentication::routes($guard)
            'prefix' => '{guard}/auth',
            'name' => 'authentication.{guard}.',
            'middleware' => ['api'],
            'authenticated_middleware' => [],    // appended after auth:{laravel_guard}
            'invitations_management' => false,
        ],

        'resources' => [
            'account' => AccountResource::class,
        ],
    ],

    'guards' => [
        'users' => [
            'model' => env('AUTHENTICATION_USERS_MODEL', 'App\\Models\\User'),
        ],
        // 'clients' => [
        //     'model' => App\Models\Client::class,
        //     'login' => ['password' => false, 'magic_link' => true, 'passkey' => true],
        //     'two_factor' => ['mode' => 'off'],
        //     'registration' => ['mode' => 'open'],
        //     'routes' => ['enabled' => true, 'prefix' => 'clients/auth'],
        // ],
    ],

];
