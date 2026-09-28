<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards;

use BackedEnum;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ThrottleLimit;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\IdentifierStorage;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\InvalidationScope;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\NotificationDelivery;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\PasskeySecondFactor;
use RoundlyConsulting\Auth\Enums\ReauthenticationMethod;
use RoundlyConsulting\Auth\Enums\RegistrationMode;
use RoundlyConsulting\Auth\Enums\RiskLevel;
use RoundlyConsulting\Auth\Enums\RiskReaction;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Enums\VerificationChannel;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;

/**
 * The effective settings of one guard: `authentication.defaults` with the guard's own
 * `authentication.guards.<name>` block merged over it.
 *
 * Every leaf is read here, by a **literal offset chain** on `$this->settings`, and only
 * here — never through an interpolated `config()` key. That keeps the config contract
 * able to see each leaf (the test maps `$this->settings` to `authentication.defaults`),
 * and gives the rest of the package typed accessors instead of arrays.
 */
final readonly class GuardConfig
{
    /**
     * @param  array<string, mixed>  $settings  the merged per-guard settings
     */
    public function __construct(
        private string $name,
        private array $settings,
    ) {}

    public function name(): string
    {
        return $this->name;
    }

    /**
     * The raw merged settings (for diagnostics — prefer the typed accessors).
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->settings;
    }

    // ── Model & wiring ───────────────────────────────────────────────────

    /**
     * @return class-string<Model&Account>
     *
     * @throws AuthenticationMisconfigured when the model is missing or not an Account model
     */
    public function model(): string
    {
        $model = $this->configuredModel();

        if ($model === null || ! is_subclass_of($model, Model::class) || ! is_subclass_of($model, Account::class)) {
            throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.model must be an Eloquent model implementing ".Account::class.'.');
        }

        /** @var class-string<Model&Account> $model */
        return $model;
    }

    /**
     * The configured model class-string, unvalidated (null when unset).
     */
    public function configuredModel(): ?string
    {
        $model = $this->settings['model'] ?? null;

        return is_string($model) && $model !== '' ? $model : null;
    }

    /**
     * The `auth.guards` key (a `jwt` guard) this guard authenticates requests with.
     */
    public function laravelGuard(): string
    {
        return $this->nullableString($this->settings['laravel_guard'] ?? null) ?? $this->name;
    }

    // ── Identifier ───────────────────────────────────────────────────────

    /**
     * @return list<string>
     */
    public function identifierColumns(): array
    {
        $columns = $this->stringList($this->settings['identifier']['columns'] ?? null);

        return $columns === [] ? [$this->emailColumn()] : $columns;
    }

    public function emailColumn(): string
    {
        return $this->nullableString($this->settings['identifier']['email_column'] ?? null) ?? 'email';
    }

    public function lowercasesIdentifiers(): bool
    {
        return ($this->settings['identifier']['normalize'] ?? 'lowercase') === 'lowercase';
    }

    public function caseInsensitiveLookup(): bool
    {
        return (bool) ($this->settings['identifier']['case_insensitive_lookup'] ?? false);
    }

    // ── Login methods ────────────────────────────────────────────────────

    public function loginMethodEnabled(LoginMethod $method): bool
    {
        return match ($method) {
            LoginMethod::Password => (bool) ($this->settings['login']['password'] ?? true),
            LoginMethod::MagicLink => (bool) ($this->settings['login']['magic_link'] ?? false),
            LoginMethod::EmailOtp => (bool) ($this->settings['login']['email_otp'] ?? false),
            LoginMethod::Passkey => (bool) ($this->settings['login']['passkey'] ?? false),
            default => true,
        };
    }

    public function revealAccountState(): bool
    {
        return (bool) ($this->settings['login']['reveal_account_state'] ?? true);
    }

    // ── Challenge ────────────────────────────────────────────────────────

    public function challengeTtl(): int
    {
        return $this->positiveInt($this->settings['challenge']['ttl'] ?? null, 300);
    }

    public function challengeEnrolmentTtl(): int
    {
        return $this->positiveInt($this->settings['challenge']['enrolment_ttl'] ?? null, 900);
    }

    public function challengeMaxAttempts(): int
    {
        return min($this->positiveInt($this->settings['challenge']['max_attempts'] ?? null, 5), 1000);
    }

    public function allowsEnrolmentInChallenge(): bool
    {
        return (bool) ($this->settings['challenge']['allow_enrolment'] ?? true);
    }

    public function enrolmentRequiresVerifiedEmail(): bool
    {
        return (bool) ($this->settings['challenge']['enrolment_requires_verified_email'] ?? true);
    }

    public function bindsChallengeToUserAgent(): bool
    {
        return (bool) ($this->settings['challenge']['bind']['user_agent'] ?? true);
    }

    public function bindsChallengeToIp(): bool
    {
        return (bool) ($this->settings['challenge']['bind']['ip'] ?? false);
    }

    public function bindsChallengeToDeviceHeader(): bool
    {
        return (bool) ($this->settings['challenge']['bind']['device_header'] ?? true);
    }

    public function maxActiveChallenges(): int
    {
        return $this->positiveInt($this->settings['challenge']['max_active_per_account'] ?? null, 3);
    }

    // ── Two-factor ───────────────────────────────────────────────────────

    public function twoFactorMode(): TwoFactorMode
    {
        return $this->enum(TwoFactorMode::class, $this->settings['two_factor']['mode'] ?? null, 'two_factor.mode');
    }

    public function twoFactorAfterEmailLogin(): bool
    {
        return (bool) ($this->settings['two_factor']['after_email_login'] ?? true);
    }

    public function twoFactorRequiredWithPasskey(): bool
    {
        return (bool) ($this->settings['two_factor']['required_with_passkey'] ?? false);
    }

    public function passkeySatisfiesRequiredTwoFactor(): bool
    {
        return (bool) ($this->settings['two_factor']['passkey_satisfies_required'] ?? true);
    }

    public function twoFactorIssuer(): ?string
    {
        return $this->nullableString($this->settings['two_factor']['issuer'] ?? null);
    }

    public function rendersQrCode(): bool
    {
        return (bool) ($this->settings['two_factor']['qr']['enabled'] ?? true);
    }

    public function qrSize(): int
    {
        return $this->positiveInt($this->settings['two_factor']['qr']['size'] ?? null, 240);
    }

    // ── Passkeys ─────────────────────────────────────────────────────────

    public function passkeyMode(): PasskeyMode
    {
        return $this->enum(PasskeyMode::class, $this->settings['passkeys']['mode'] ?? null, 'passkeys.mode');
    }

    public function passkeySecondFactor(): PasskeySecondFactor
    {
        return $this->enum(PasskeySecondFactor::class, $this->settings['passkeys']['second_factor'] ?? null, 'passkeys.second_factor');
    }

    public function passkeySatisfiesMfa(): bool
    {
        return (bool) ($this->settings['passkeys']['satisfies_mfa'] ?? true);
    }

    // ── Tokens & sessions ────────────────────────────────────────────────

    public function accessTtl(): ?int
    {
        $ttl = $this->settings['tokens']['access_ttl'] ?? null;

        return is_numeric($ttl) && (int) $ttl > 0 ? (int) $ttl : null;
    }

    public function refreshTtl(): int
    {
        return $this->positiveInt($this->settings['tokens']['refresh_ttl'] ?? null, 2_592_000);
    }

    public function refreshAbsoluteTtl(): int
    {
        $ttl = $this->settings['tokens']['refresh_absolute_ttl'] ?? null;

        return is_numeric($ttl) && (int) $ttl >= 0 ? (int) $ttl : 7_776_000;
    }

    public function claimsResolver(): ?string
    {
        return $this->nullableString($this->settings['tokens']['claims_resolver'] ?? null);
    }

    public function includesEmailClaim(): bool
    {
        return (bool) ($this->settings['tokens']['include_email'] ?? true);
    }

    public function maxActiveSessions(): ?int
    {
        $max = $this->settings['sessions']['max_active'] ?? null;

        return is_numeric($max) && (int) $max > 0 ? (int) $max : null;
    }

    public function invalidationScope(InvalidationReason $reason): InvalidationScope
    {
        $configured = match ($reason) {
            InvalidationReason::PasswordChanged => $this->settings['invalidation']['password_changed'] ?? 'others',
            InvalidationReason::PasswordReset => $this->settings['invalidation']['password_reset'] ?? 'all',
            InvalidationReason::EmailChanged => $this->settings['invalidation']['email_changed'] ?? 'others',
            InvalidationReason::TwoFactorChanged => $this->settings['invalidation']['two_factor_changed'] ?? 'others',
            InvalidationReason::PasskeyChanged => $this->settings['invalidation']['passkey_changed'] ?? 'none',
            // Never configurable below `all`.
            InvalidationReason::AccountDisabled, InvalidationReason::Logout, InvalidationReason::Security => 'all',
        };

        return $this->enum(InvalidationScope::class, $configured, 'invalidation.'.$reason->value);
    }

    // ── Registration & invitations ───────────────────────────────────────

    public function registrationMode(): RegistrationMode
    {
        return $this->enum(RegistrationMode::class, $this->settings['registration']['mode'] ?? null, 'registration.mode');
    }

    public function registrationRequiresPassword(): bool
    {
        return $this->loginMethodEnabled(LoginMethod::Password)
            && (bool) ($this->settings['registration']['require_password'] ?? true);
    }

    public function loginAfterRegistration(): bool
    {
        return (bool) ($this->settings['registration']['login_after'] ?? true);
    }

    public function registrationRules(): ?string
    {
        return $this->nullableString($this->settings['registration']['rules'] ?? null);
    }

    public function accountCreator(): ?string
    {
        return $this->nullableString($this->settings['registration']['creator'] ?? null);
    }

    public function invitationsEnabled(): bool
    {
        return (bool) ($this->settings['invitations']['enabled'] ?? false);
    }

    public function invitationTtl(): int
    {
        return $this->positiveInt($this->settings['invitations']['ttl'] ?? null, 604_800);
    }

    public function invitationLocksEmail(): bool
    {
        return (bool) ($this->settings['invitations']['lock_email'] ?? true);
    }

    public function invitationReplacesPending(): bool
    {
        return (bool) ($this->settings['invitations']['replace_pending'] ?? true);
    }

    public function invitationAllowsExistingEmail(): bool
    {
        return (bool) ($this->settings['invitations']['allow_existing_email'] ?? false);
    }

    public function invitationResendCooldown(): int
    {
        return max(0, (int) ($this->settings['invitations']['resend_cooldown'] ?? 60));
    }

    public function invitationMaxSends(): int
    {
        return min($this->positiveInt($this->settings['invitations']['max_sends'] ?? null, 5), 1000);
    }

    /**
     * @return list<string>
     */
    public function invitationPreviewPayloadKeys(): array
    {
        return $this->stringList($this->settings['invitations']['preview_payload_keys'] ?? null);
    }

    public function invitationAbility(): string
    {
        return $this->nullableString($this->settings['invitations']['ability'] ?? null) ?? 'authentication.invitations.manage';
    }

    // ── Email verification & change ──────────────────────────────────────

    public function verificationMode(): EmailVerificationMode
    {
        return $this->enum(EmailVerificationMode::class, $this->settings['verification']['mode'] ?? null, 'verification.mode');
    }

    public function verificationChannel(): VerificationChannel
    {
        return $this->enum(VerificationChannel::class, $this->settings['verification']['channel'] ?? null, 'verification.channel');
    }

    public function verificationResendDecay(): int
    {
        return max(0, (int) ($this->settings['verification']['resend_decay'] ?? 60));
    }

    public function verifiesEmailOnEmailLogin(): bool
    {
        return (bool) ($this->settings['verification']['verify_on_email_login'] ?? true);
    }

    public function emailChangeEnabled(): bool
    {
        return (bool) ($this->settings['email_change']['enabled'] ?? true);
    }

    public function emailChangeNotifiesOldAddress(): bool
    {
        return (bool) ($this->settings['email_change']['notify_old'] ?? true);
    }

    public function emailChangeRequiresReauthentication(): bool
    {
        return (bool) ($this->settings['email_change']['require_reauthentication'] ?? true);
    }

    public function magicLinkSameDevice(): bool
    {
        return (bool) ($this->settings['magic_link']['same_device'] ?? false);
    }

    // ── One-time secrets ─────────────────────────────────────────────────

    /**
     * Lifetime (seconds) of a one-time secret. Re-authentication codes share the
     * email-OTP settings.
     */
    public function ttl(OneTimeTokenPurpose $purpose): int
    {
        return match ($purpose) {
            OneTimeTokenPurpose::MagicLink => $this->positiveInt($this->settings['magic_link']['ttl'] ?? null, 900),
            OneTimeTokenPurpose::EmailOtp, OneTimeTokenPurpose::Reauthentication => $this->positiveInt($this->settings['email_otp']['ttl'] ?? null, 600),
            OneTimeTokenPurpose::EmailVerification => $this->positiveInt($this->settings['verification']['ttl'] ?? null, 86_400),
            OneTimeTokenPurpose::PasswordReset => $this->positiveInt($this->settings['passwords']['reset']['ttl'] ?? null, 3_600),
            OneTimeTokenPurpose::EmailChange => $this->positiveInt($this->settings['email_change']['ttl'] ?? null, 3_600),
        };
    }

    /**
     * Whether the purpose uses a short typed code (vs a link token).
     */
    public function usesCode(OneTimeTokenPurpose $purpose): bool
    {
        return match ($purpose) {
            OneTimeTokenPurpose::EmailOtp, OneTimeTokenPurpose::Reauthentication => true,
            OneTimeTokenPurpose::EmailVerification => $this->verificationChannel() === VerificationChannel::Code,
            default => false,
        };
    }

    public function codeLength(OneTimeTokenPurpose $purpose): int
    {
        $length = $purpose === OneTimeTokenPurpose::EmailVerification
            ? ($this->settings['verification']['code_length'] ?? 6)
            : ($this->settings['email_otp']['length'] ?? 6);

        return max(6, min(8, (int) $length));
    }

    public function codeMaxAttempts(OneTimeTokenPurpose $purpose): int
    {
        $attempts = $purpose === OneTimeTokenPurpose::EmailVerification
            ? ($this->settings['verification']['max_attempts'] ?? 5)
            : ($this->settings['email_otp']['max_attempts'] ?? 5);

        return max(1, min(100, (int) $attempts));
    }

    // ── Passwords ────────────────────────────────────────────────────────

    public function passwordResetEnabled(): bool
    {
        return $this->loginMethodEnabled(LoginMethod::Password)
            && (bool) ($this->settings['passwords']['reset']['enabled'] ?? true);
    }

    public function loginAfterPasswordReset(): bool
    {
        return (bool) ($this->settings['passwords']['reset']['login_after'] ?? false);
    }

    public function passwordChangeEnabled(): bool
    {
        return (bool) ($this->settings['passwords']['change']['enabled'] ?? true);
    }

    public function rehashesPasswordsOnLogin(): bool
    {
        return (bool) ($this->settings['passwords']['rehash_on_login'] ?? true);
    }

    public function passwordMinLength(): int
    {
        return $this->positiveInt($this->settings['passwords']['policy']['min'] ?? null, 10);
    }

    public function passwordMaxLength(): int
    {
        return max($this->passwordMinLength(), $this->positiveInt($this->settings['passwords']['policy']['max'] ?? null, 128));
    }

    public function passwordRequiresLetters(): bool
    {
        return (bool) ($this->settings['passwords']['policy']['letters'] ?? false);
    }

    public function passwordRequiresMixedCase(): bool
    {
        return (bool) ($this->settings['passwords']['policy']['mixed_case'] ?? false);
    }

    public function passwordRequiresNumbers(): bool
    {
        return (bool) ($this->settings['passwords']['policy']['numbers'] ?? false);
    }

    public function passwordRequiresSymbols(): bool
    {
        return (bool) ($this->settings['passwords']['policy']['symbols'] ?? false);
    }

    public function passwordMustNotContainIdentifier(): bool
    {
        return (bool) ($this->settings['passwords']['policy']['not_identifier'] ?? true);
    }

    public function breachCheckEnabled(): bool
    {
        return (bool) ($this->settings['passwords']['policy']['uncompromised']['enabled'] ?? false);
    }

    public function breachThreshold(): int
    {
        return max(0, (int) ($this->settings['passwords']['policy']['uncompromised']['threshold'] ?? 0));
    }

    public function breachCheckTimeout(): int
    {
        return $this->positiveInt($this->settings['passwords']['policy']['uncompromised']['timeout'] ?? null, 3);
    }

    public function breachCheckFailsClosed(): bool
    {
        return (bool) ($this->settings['passwords']['policy']['uncompromised']['fail_closed'] ?? false);
    }

    // ── Throttling & lockout ─────────────────────────────────────────────

    public function throttle(ThrottleKind $kind): ThrottleLimit
    {
        return match ($kind) {
            ThrottleKind::Login => $this->limit($this->settings['throttle']['login']['max'] ?? null, $this->settings['throttle']['login']['decay'] ?? null, 5, 60),
            ThrottleKind::LoginIp => $this->limit($this->settings['throttle']['login_ip']['max'] ?? null, $this->settings['throttle']['login_ip']['decay'] ?? null, 50, 600),
            ThrottleKind::LoginAccount => $this->limit($this->settings['throttle']['login_account']['max'] ?? null, $this->settings['throttle']['login_account']['decay'] ?? null, 20, 3_600),
            ThrottleKind::EmailRequest => $this->limit($this->settings['throttle']['email_request']['max'] ?? null, $this->settings['throttle']['email_request']['decay'] ?? null, 3, 600),
            ThrottleKind::EmailRequestIp => $this->limit($this->settings['throttle']['email_request_ip']['max'] ?? null, $this->settings['throttle']['email_request_ip']['decay'] ?? null, 20, 600),
            ThrottleKind::EmailRequestAccount => $this->limit($this->settings['throttle']['email_request_account']['max'] ?? null, $this->settings['throttle']['email_request_account']['decay'] ?? null, 10, 3_600),
            ThrottleKind::Refresh => $this->limit($this->settings['throttle']['refresh']['max'] ?? null, $this->settings['throttle']['refresh']['decay'] ?? null, 30, 60),
            ThrottleKind::Registration => $this->limit($this->settings['throttle']['registration']['max'] ?? null, $this->settings['throttle']['registration']['decay'] ?? null, 5, 3_600),
            ThrottleKind::Verification => $this->limit($this->settings['throttle']['verification']['max'] ?? null, $this->settings['throttle']['verification']['decay'] ?? null, 5, 600),
            ThrottleKind::Reauthentication => $this->limit($this->settings['throttle']['reauthentication']['max'] ?? null, $this->settings['throttle']['reauthentication']['decay'] ?? null, 5, 300),
        };
    }

    public function lockoutEnabled(): bool
    {
        return (bool) ($this->settings['lockout']['enabled'] ?? false);
    }

    public function lockoutThreshold(): int
    {
        return min($this->positiveInt($this->settings['lockout']['threshold'] ?? null, 10), 1_000_000);
    }

    public function lockoutDuration(): int
    {
        return $this->positiveInt($this->settings['lockout']['duration'] ?? null, 900);
    }

    public function passwordResetUnlocks(): bool
    {
        return (bool) ($this->settings['lockout']['reset_unlocks'] ?? true);
    }

    // ── Re-authentication ────────────────────────────────────────────────

    public function reauthenticationTimeout(): int
    {
        return $this->positiveInt($this->settings['reauthentication']['timeout'] ?? null, 900);
    }

    /**
     * @return list<ReauthenticationMethod>
     */
    public function reauthenticationMethods(): array
    {
        return $this->enumList(ReauthenticationMethod::class, $this->settings['reauthentication']['methods'] ?? null, 'reauthentication.methods');
    }

    public function reauthenticationRequiresSecondFactorWhenEnrolled(): bool
    {
        return (bool) ($this->settings['reauthentication']['require_second_factor_when_enrolled'] ?? true);
    }

    public function freshLoginCountsAsReauthentication(): bool
    {
        return (bool) ($this->settings['reauthentication']['fresh_login_counts'] ?? true);
    }

    /**
     * Whether the action needs a recent re-authentication: listed in
     * `reauthentication.required_for` — and, for an email change, not switched off by
     * `email_change.require_reauthentication = false`.
     */
    public function requiresReauthentication(SensitiveAction $action): bool
    {
        if ($action === SensitiveAction::ChangeEmail && ! $this->emailChangeRequiresReauthentication()) {
            return false;
        }

        return in_array($action, $this->sensitiveActions(), true);
    }

    /**
     * The actions behind a recent re-authentication (`reauthentication.required_for`).
     *
     * @return list<SensitiveAction>
     */
    public function sensitiveActions(): array
    {
        return $this->enumList(SensitiveAction::class, $this->settings['reauthentication']['required_for'] ?? null, 'reauthentication.required_for');
    }

    // ── Activity & risk ──────────────────────────────────────────────────

    public function activityEnabled(): bool
    {
        return (bool) ($this->settings['activity']['enabled'] ?? true);
    }

    public function identifierStorage(): IdentifierStorage
    {
        return $this->enum(IdentifierStorage::class, $this->settings['activity']['store_identifier'] ?? null, 'activity.store_identifier');
    }

    public function activityRetentionDays(): int
    {
        return $this->positiveInt($this->settings['activity']['retention_days'] ?? null, 90);
    }

    public function newDeviceDetectionEnabled(): bool
    {
        return (bool) ($this->settings['activity']['new_device']['enabled'] ?? true);
    }

    public function newDeviceHeader(): string
    {
        return $this->nullableString($this->settings['activity']['new_device']['header'] ?? null) ?? 'X-Device-Id';
    }

    public function newDeviceSkipsFirstLogin(): bool
    {
        return (bool) ($this->settings['activity']['new_device']['skip_first_login'] ?? true);
    }

    public function riskAssessor(): ?string
    {
        return $this->nullableString($this->settings['risk']['assessor'] ?? null);
    }

    public function riskReaction(RiskLevel $level): RiskReaction
    {
        return match ($level) {
            RiskLevel::Low => RiskReaction::Allow,
            RiskLevel::Elevated => $this->enum(RiskReaction::class, $this->settings['risk']['reactions']['elevated'] ?? 'notify', 'risk.reactions.elevated'),
            RiskLevel::High => $this->enum(RiskReaction::class, $this->settings['risk']['reactions']['high'] ?? 'require_second_factor', 'risk.reactions.high'),
        };
    }

    public function riskDenialIsUniform(): bool
    {
        return ($this->settings['risk']['deny_response'] ?? 'uniform') !== 'explicit';
    }

    // ── Locale ───────────────────────────────────────────────────────────

    public function localeHeader(): ?string
    {
        return $this->nullableString($this->settings['locale']['header'] ?? null);
    }

    /**
     * @return list<string>
     */
    public function supportedLocales(): array
    {
        $supported = $this->stringList($this->settings['locale']['supported'] ?? null);

        if ($supported !== []) {
            return $supported;
        }

        $default = config('app.locale');

        return [is_string($default) && $default !== '' ? $default : 'en'];
    }

    public function storesLocaleOnRegistration(): bool
    {
        return (bool) ($this->settings['locale']['store_on_registration'] ?? true);
    }

    public function fillsLocaleOnLogin(): bool
    {
        return (bool) ($this->settings['locale']['fill_on_login'] ?? true);
    }

    public function timezonesEnabled(): bool
    {
        return (bool) ($this->settings['locale']['timezone'] ?? true);
    }

    // ── Notifications ────────────────────────────────────────────────────

    public function notificationDelivery(): NotificationDelivery
    {
        return $this->enum(NotificationDelivery::class, $this->settings['notifications']['delivery'] ?? null, 'notifications.delivery');
    }

    public function notificationConnection(): ?string
    {
        return $this->nullableString($this->settings['notifications']['connection'] ?? null);
    }

    public function notificationQueue(): ?string
    {
        return $this->nullableString($this->settings['notifications']['queue'] ?? null);
    }

    /**
     * The configured class for a notification, or null when the host disabled it.
     */
    public function notificationClass(NotificationType $type): ?string
    {
        return $this->nullableString(match ($type) {
            NotificationType::MagicLink => $this->settings['notifications']['classes']['magic_link'] ?? null,
            NotificationType::EmailOtp => $this->settings['notifications']['classes']['email_otp'] ?? null,
            NotificationType::VerifyEmail => $this->settings['notifications']['classes']['verify_email'] ?? null,
            NotificationType::ResetPassword => $this->settings['notifications']['classes']['reset_password'] ?? null,
            NotificationType::PasswordChanged => $this->settings['notifications']['classes']['password_changed'] ?? null,
            NotificationType::EmailChangeConfirmation => $this->settings['notifications']['classes']['email_change_confirmation'] ?? null,
            NotificationType::EmailChangeRequested => $this->settings['notifications']['classes']['email_change_requested'] ?? null,
            NotificationType::EmailChanged => $this->settings['notifications']['classes']['email_changed'] ?? null,
            NotificationType::AccountExists => $this->settings['notifications']['classes']['account_exists'] ?? null,
            NotificationType::Invitation => $this->settings['notifications']['classes']['invitation'] ?? null,
            NotificationType::NewDevice => $this->settings['notifications']['classes']['new_device'] ?? null,
            NotificationType::TwoFactorEnabled => $this->settings['notifications']['classes']['two_factor_enabled'] ?? null,
            NotificationType::TwoFactorDisabled => $this->settings['notifications']['classes']['two_factor_disabled'] ?? null,
            NotificationType::RecoveryCodeUsed => $this->settings['notifications']['classes']['recovery_code_used'] ?? null,
            NotificationType::PasskeyAdded => $this->settings['notifications']['classes']['passkey_added'] ?? null,
            NotificationType::PasskeyRemoved => $this->settings['notifications']['classes']['passkey_removed'] ?? null,
            NotificationType::AccountLocked => $this->settings['notifications']['classes']['account_locked'] ?? null,
            NotificationType::RefreshTokenReuse => $this->settings['notifications']['classes']['refresh_token_reuse'] ?? null,
        });
    }

    public function frontendUrl(): string
    {
        $url = $this->nullableString($this->settings['notifications']['frontend_url'] ?? null) ?? $this->appUrl();

        return rtrim($url, '/');
    }

    public function appUrl(): string
    {
        $url = config('app.url');

        return rtrim(is_string($url) && $url !== '' ? $url : 'http://localhost', '/');
    }

    public function urlTemplate(UrlKind $kind): string
    {
        $template = match ($kind) {
            UrlKind::MagicLink => $this->settings['notifications']['urls']['magic_link'] ?? null,
            UrlKind::VerifyEmail => $this->settings['notifications']['urls']['verify_email'] ?? null,
            UrlKind::ResetPassword => $this->settings['notifications']['urls']['reset_password'] ?? null,
            UrlKind::ConfirmEmailChange => $this->settings['notifications']['urls']['confirm_email_change'] ?? null,
            UrlKind::Invitation => $this->settings['notifications']['urls']['invitation'] ?? null,
        };

        // Blanked (e.g. an empty env var): the shipped default's path, never a guessed one.
        $path = match ($kind) {
            UrlKind::MagicLink => 'magic-link',
            UrlKind::VerifyEmail => 'verify-email',
            UrlKind::ResetPassword => 'reset-password',
            UrlKind::ConfirmEmailChange => 'confirm-email',
            UrlKind::Invitation => 'invitation',
        };

        return $this->nullableString($template) ?? '{frontend}/auth/'.$path.'?guard={guard}#token={token}';
    }

    // ── Routes & resources ───────────────────────────────────────────────

    public function routesEnabled(): bool
    {
        return (bool) ($this->settings['routes']['enabled'] ?? false);
    }

    public function routePrefix(): string
    {
        $prefix = $this->nullableString($this->settings['routes']['prefix'] ?? null) ?? '{guard}/auth';

        return trim(str_replace('{guard}', $this->name, $prefix), '/');
    }

    public function routeName(): string
    {
        $name = $this->nullableString($this->settings['routes']['name'] ?? null) ?? 'authentication.{guard}.';

        return str_replace('{guard}', $this->name, $name);
    }

    /**
     * @return list<string>
     */
    public function routeMiddleware(): array
    {
        return $this->stringList($this->settings['routes']['middleware'] ?? null);
    }

    /**
     * @return list<string>
     */
    public function authenticatedRouteMiddleware(): array
    {
        return $this->stringList($this->settings['routes']['authenticated_middleware'] ?? null);
    }

    public function invitationManagementRoutes(): bool
    {
        return (bool) ($this->settings['routes']['invitations_management'] ?? false);
    }

    public function accountResource(): ?string
    {
        return $this->nullableString($this->settings['resources']['account'] ?? null);
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /**
     * @template TEnum of BackedEnum
     *
     * @param  class-string<TEnum>  $enum
     * @return TEnum
     */
    private function enum(string $enum, mixed $value, string $key): BackedEnum
    {
        if ($value instanceof $enum) {
            return $value;
        }

        $case = is_string($value) ? $enum::tryFrom($value) : null;

        if ($case === null) {
            throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.{$key} is not a valid value.");
        }

        return $case;
    }

    /**
     * An unknown entry fails loudly: silently dropping `disable_2fa` from `required_for`
     * would switch that gate off.
     *
     * @template TEnum of BackedEnum
     *
     * @param  class-string<TEnum>  $enum
     * @return list<TEnum>
     *
     * @throws AuthenticationMisconfigured
     */
    private function enumList(string $enum, mixed $values, string $key): array
    {
        $cases = [];

        foreach ($this->stringList($values) as $value) {
            $case = $enum::tryFrom($value) ?? throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.{$key} contains the unknown value [{$value}].");

            if (! in_array($case, $cases, true)) {
                $cases[] = $case;
            }
        }

        return $cases;
    }

    /**
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn (mixed $item): bool => is_string($item) && $item !== ''));
    }

    private function nullableString(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? $value : null;
    }

    private function positiveInt(mixed $value, int $default): int
    {
        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }

    private function limit(mixed $max, mixed $decay, int $defaultMax, int $defaultDecay): ThrottleLimit
    {
        return new ThrottleLimit($this->positiveInt($max, $defaultMax), $this->positiveInt($decay, $defaultDecay));
    }
}
