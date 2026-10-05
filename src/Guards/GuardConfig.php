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
use RoundlyConsulting\Auth\Notifications\SignInBlockedNotification;
use RoundlyConsulting\Auth\Notifications\UnusualSignInNotification;
use RoundlyConsulting\PackageToolkit\Exceptions\InvalidConfigurationException;
use RoundlyConsulting\PackageToolkit\Support\Config;

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

        return is_string($model) && trim($model) !== '' ? $model : null;
    }

    /**
     * The `auth.guards` key (a `jwt` guard) this guard authenticates requests with.
     */
    public function laravelGuard(): string
    {
        return $this->optionalString($this->settings['laravel_guard'] ?? null, 'laravel_guard') ?? $this->name;
    }

    // ── Identifier ───────────────────────────────────────────────────────

    /**
     * @return list<string>
     */
    public function identifierColumns(): array
    {
        $columns = $this->stringList($this->settings['identifier']['columns'] ?? null, 'identifier.columns');

        return $columns === [] ? [$this->emailColumn()] : $columns;
    }

    public function emailColumn(): string
    {
        return $this->requiredString($this->settings['identifier']['email_column'] ?? null, 'identifier.email_column', 'email');
    }

    public function lowercasesIdentifiers(): bool
    {
        return $this->choice($this->settings['identifier']['normalize'] ?? null, 'identifier.normalize', 'lowercase', 'none', true);
    }

    public function caseInsensitiveLookup(): bool
    {
        return $this->flag($this->settings['identifier']['case_insensitive_lookup'] ?? null, 'identifier.case_insensitive_lookup', false);
    }

    // ── Login methods ────────────────────────────────────────────────────

    public function loginMethodEnabled(LoginMethod $method): bool
    {
        return match ($method) {
            LoginMethod::Password => $this->flag($this->settings['login']['password'] ?? null, 'login.password', true),
            LoginMethod::MagicLink => $this->flag($this->settings['login']['magic_link'] ?? null, 'login.magic_link', false),
            LoginMethod::EmailOtp => $this->flag($this->settings['login']['email_otp'] ?? null, 'login.email_otp', false),
            LoginMethod::Passkey => $this->flag($this->settings['login']['passkey'] ?? null, 'login.passkey', false),
            default => true,
        };
    }

    public function revealAccountState(): bool
    {
        return $this->flag($this->settings['login']['reveal_account_state'] ?? null, 'login.reveal_account_state', true);
    }

    // ── Challenge ────────────────────────────────────────────────────────

    public function challengeTtl(): int
    {
        return $this->integer($this->settings['challenge']['ttl'] ?? null, 'challenge.ttl', 300);
    }

    public function challengeEnrolmentTtl(): int
    {
        return $this->integer($this->settings['challenge']['enrolment_ttl'] ?? null, 'challenge.enrolment_ttl', 900);
    }

    public function challengeMaxAttempts(): int
    {
        return $this->integer($this->settings['challenge']['max_attempts'] ?? null, 'challenge.max_attempts', 5, max: 1000);
    }

    public function allowsEnrolmentInChallenge(): bool
    {
        return $this->flag($this->settings['challenge']['allow_enrolment'] ?? null, 'challenge.allow_enrolment', true);
    }

    public function enrolmentRequiresVerifiedEmail(): bool
    {
        return $this->flag($this->settings['challenge']['enrolment_requires_verified_email'] ?? null, 'challenge.enrolment_requires_verified_email', true);
    }

    public function bindsChallengeToUserAgent(): bool
    {
        return $this->flag($this->settings['challenge']['bind']['user_agent'] ?? null, 'challenge.bind.user_agent', true);
    }

    public function bindsChallengeToIp(): bool
    {
        return $this->flag($this->settings['challenge']['bind']['ip'] ?? null, 'challenge.bind.ip', false);
    }

    public function bindsChallengeToDeviceHeader(): bool
    {
        return $this->flag($this->settings['challenge']['bind']['device_header'] ?? null, 'challenge.bind.device_header', true);
    }

    public function maxActiveChallenges(): int
    {
        return $this->integer($this->settings['challenge']['max_active_per_account'] ?? null, 'challenge.max_active_per_account', 3);
    }

    // ── Two-factor ───────────────────────────────────────────────────────

    public function twoFactorMode(): TwoFactorMode
    {
        return $this->enum(TwoFactorMode::class, $this->settings['two_factor']['mode'] ?? null, 'two_factor.mode', TwoFactorMode::Optional);
    }

    public function twoFactorAfterEmailLogin(): bool
    {
        return $this->flag($this->settings['two_factor']['after_email_login'] ?? null, 'two_factor.after_email_login', true);
    }

    public function twoFactorRequiredWithPasskey(): bool
    {
        return $this->flag($this->settings['two_factor']['required_with_passkey'] ?? null, 'two_factor.required_with_passkey', false);
    }

    public function passkeySatisfiesRequiredTwoFactor(): bool
    {
        return $this->flag($this->settings['two_factor']['passkey_satisfies_required'] ?? null, 'two_factor.passkey_satisfies_required', true);
    }

    public function twoFactorIssuer(): ?string
    {
        return $this->optionalString($this->settings['two_factor']['issuer'] ?? null, 'two_factor.issuer');
    }

    public function rendersQrCode(): bool
    {
        return $this->flag($this->settings['two_factor']['qr']['enabled'] ?? null, 'two_factor.qr.enabled', true);
    }

    public function qrSize(): int
    {
        return $this->integer($this->settings['two_factor']['qr']['size'] ?? null, 'two_factor.qr.size', 240);
    }

    // ── Passkeys ─────────────────────────────────────────────────────────

    public function passkeyMode(): PasskeyMode
    {
        return $this->enum(PasskeyMode::class, $this->settings['passkeys']['mode'] ?? null, 'passkeys.mode', PasskeyMode::Optional);
    }

    public function passkeySecondFactor(): PasskeySecondFactor
    {
        return $this->enum(PasskeySecondFactor::class, $this->settings['passkeys']['second_factor'] ?? null, 'passkeys.second_factor', PasskeySecondFactor::Allowed);
    }

    public function passkeySatisfiesMfa(): bool
    {
        return $this->flag($this->settings['passkeys']['satisfies_mfa'] ?? null, 'passkeys.satisfies_mfa', true);
    }

    // ── Tokens & sessions ────────────────────────────────────────────────

    public function accessTtl(): ?int
    {
        $ttl = $this->settings['tokens']['access_ttl'] ?? null;

        return self::notSet($ttl) ? null : $this->integer($ttl, 'tokens.access_ttl', 0, min: 1);
    }

    public function refreshTtl(): int
    {
        return $this->integer($this->settings['tokens']['refresh_ttl'] ?? null, 'tokens.refresh_ttl', 2_592_000);
    }

    public function refreshAbsoluteTtl(): int
    {
        return $this->integer($this->settings['tokens']['refresh_absolute_ttl'] ?? null, 'tokens.refresh_absolute_ttl', 7_776_000, min: 0);
    }

    public function claimsResolver(): ?string
    {
        return $this->optionalString($this->settings['tokens']['claims_resolver'] ?? null, 'tokens.claims_resolver');
    }

    public function includesEmailClaim(): bool
    {
        return $this->flag($this->settings['tokens']['include_email'] ?? null, 'tokens.include_email', true);
    }

    public function maxActiveSessions(): ?int
    {
        $max = $this->settings['sessions']['max_active'] ?? null;

        return self::notSet($max) ? null : $this->integer($max, 'sessions.max_active', 0, min: 1);
    }

    public function invalidationScope(InvalidationReason $reason): InvalidationScope
    {
        $configured = match ($reason) {
            InvalidationReason::PasswordChanged => [$this->settings['invalidation']['password_changed'] ?? null, InvalidationScope::Others],
            InvalidationReason::PasswordReset => [$this->settings['invalidation']['password_reset'] ?? null, InvalidationScope::All],
            InvalidationReason::EmailChanged => [$this->settings['invalidation']['email_changed'] ?? null, InvalidationScope::Others],
            InvalidationReason::TwoFactorChanged => [$this->settings['invalidation']['two_factor_changed'] ?? null, InvalidationScope::Others],
            InvalidationReason::PasskeyChanged => [$this->settings['invalidation']['passkey_changed'] ?? null, InvalidationScope::None],
            // Never configurable below `all`.
            InvalidationReason::AccountDisabled, InvalidationReason::Logout, InvalidationReason::Security => [InvalidationScope::All, InvalidationScope::All],
        };

        return $this->enum(InvalidationScope::class, $configured[0], 'invalidation.'.$reason->value, $configured[1]);
    }

    // ── Registration & invitations ───────────────────────────────────────

    public function registrationMode(): RegistrationMode
    {
        return $this->enum(RegistrationMode::class, $this->settings['registration']['mode'] ?? null, 'registration.mode', RegistrationMode::Closed);
    }

    public function registrationRequiresPassword(): bool
    {
        // Read before the password gate, so a typo fails even while password login is off.
        $required = $this->flag($this->settings['registration']['require_password'] ?? null, 'registration.require_password', true);

        return $this->loginMethodEnabled(LoginMethod::Password) && $required;
    }

    public function loginAfterRegistration(): bool
    {
        return $this->flag($this->settings['registration']['login_after'] ?? null, 'registration.login_after', true);
    }

    public function registrationRules(): ?string
    {
        return $this->optionalString($this->settings['registration']['rules'] ?? null, 'registration.rules');
    }

    public function accountCreator(): ?string
    {
        return $this->optionalString($this->settings['registration']['creator'] ?? null, 'registration.creator');
    }

    public function invitationsEnabled(): bool
    {
        return $this->flag($this->settings['invitations']['enabled'] ?? null, 'invitations.enabled', false);
    }

    public function invitationTtl(): int
    {
        return $this->integer($this->settings['invitations']['ttl'] ?? null, 'invitations.ttl', 604_800);
    }

    public function invitationLocksEmail(): bool
    {
        return $this->flag($this->settings['invitations']['lock_email'] ?? null, 'invitations.lock_email', true);
    }

    public function invitationReplacesPending(): bool
    {
        return $this->flag($this->settings['invitations']['replace_pending'] ?? null, 'invitations.replace_pending', true);
    }

    public function invitationAllowsExistingEmail(): bool
    {
        return $this->flag($this->settings['invitations']['allow_existing_email'] ?? null, 'invitations.allow_existing_email', false);
    }

    public function invitationResendCooldown(): int
    {
        return $this->integer($this->settings['invitations']['resend_cooldown'] ?? null, 'invitations.resend_cooldown', 60, min: 0);
    }

    public function invitationMaxSends(): int
    {
        return $this->integer($this->settings['invitations']['max_sends'] ?? null, 'invitations.max_sends', 5, max: 1000);
    }

    /**
     * @return list<string>
     */
    public function invitationPreviewPayloadKeys(): array
    {
        return $this->stringList($this->settings['invitations']['preview_payload_keys'] ?? null, 'invitations.preview_payload_keys');
    }

    public function invitationAbility(): string
    {
        return $this->requiredString($this->settings['invitations']['ability'] ?? null, 'invitations.ability', 'authentication.invitations.manage');
    }

    // ── Email verification & change ──────────────────────────────────────

    public function verificationMode(): EmailVerificationMode
    {
        return $this->enum(EmailVerificationMode::class, $this->settings['verification']['mode'] ?? null, 'verification.mode', EmailVerificationMode::Optional);
    }

    public function verificationChannel(): VerificationChannel
    {
        return $this->enum(VerificationChannel::class, $this->settings['verification']['channel'] ?? null, 'verification.channel', VerificationChannel::Link);
    }

    public function verificationResendDecay(): int
    {
        return $this->integer($this->settings['verification']['resend_decay'] ?? null, 'verification.resend_decay', 60, min: 0);
    }

    public function verifiesEmailOnEmailLogin(): bool
    {
        return $this->flag($this->settings['verification']['verify_on_email_login'] ?? null, 'verification.verify_on_email_login', true);
    }

    public function emailChangeEnabled(): bool
    {
        return $this->flag($this->settings['email_change']['enabled'] ?? null, 'email_change.enabled', true);
    }

    public function emailChangeNotifiesOldAddress(): bool
    {
        return $this->flag($this->settings['email_change']['notify_old'] ?? null, 'email_change.notify_old', true);
    }

    public function emailChangeRequiresReauthentication(): bool
    {
        return $this->flag($this->settings['email_change']['require_reauthentication'] ?? null, 'email_change.require_reauthentication', true);
    }

    public function magicLinkSameDevice(): bool
    {
        return $this->flag($this->settings['magic_link']['same_device'] ?? null, 'magic_link.same_device', false);
    }

    // ── One-time secrets ─────────────────────────────────────────────────

    /**
     * Lifetime (seconds) of a one-time secret. Re-authentication codes share the
     * email-OTP settings.
     */
    public function ttl(OneTimeTokenPurpose $purpose): int
    {
        return match ($purpose) {
            OneTimeTokenPurpose::MagicLink => $this->integer($this->settings['magic_link']['ttl'] ?? null, 'magic_link.ttl', 900),
            OneTimeTokenPurpose::EmailOtp, OneTimeTokenPurpose::Reauthentication => $this->integer($this->settings['email_otp']['ttl'] ?? null, 'email_otp.ttl', 600),
            OneTimeTokenPurpose::EmailVerification => $this->integer($this->settings['verification']['ttl'] ?? null, 'verification.ttl', 86_400),
            OneTimeTokenPurpose::PasswordReset => $this->integer($this->settings['passwords']['reset']['ttl'] ?? null, 'passwords.reset.ttl', 3_600),
            OneTimeTokenPurpose::EmailChange => $this->integer($this->settings['email_change']['ttl'] ?? null, 'email_change.ttl', 3_600),
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
        return $purpose === OneTimeTokenPurpose::EmailVerification
            ? $this->integer($this->settings['verification']['code_length'] ?? null, 'verification.code_length', 6, min: 6, max: 8)
            : $this->integer($this->settings['email_otp']['length'] ?? null, 'email_otp.length', 6, min: 6, max: 8);
    }

    public function codeMaxAttempts(OneTimeTokenPurpose $purpose): int
    {
        return $purpose === OneTimeTokenPurpose::EmailVerification
            ? $this->integer($this->settings['verification']['max_attempts'] ?? null, 'verification.max_attempts', 5, min: 1, max: 100)
            : $this->integer($this->settings['email_otp']['max_attempts'] ?? null, 'email_otp.max_attempts', 5, min: 1, max: 100);
    }

    // ── Passwords ────────────────────────────────────────────────────────

    public function passwordResetEnabled(): bool
    {
        return $this->passwordResetSwitchedOn() && $this->loginMethodEnabled(LoginMethod::Password);
    }

    /**
     * The `passwords.reset.enabled` switch itself, before `login.password` gates it (the
     * doctor warns when it is on but ignored).
     */
    public function passwordResetSwitchedOn(): bool
    {
        return $this->flag($this->settings['passwords']['reset']['enabled'] ?? null, 'passwords.reset.enabled', true);
    }

    public function loginAfterPasswordReset(): bool
    {
        return $this->flag($this->settings['passwords']['reset']['login_after'] ?? null, 'passwords.reset.login_after', false);
    }

    public function passwordChangeEnabled(): bool
    {
        return $this->flag($this->settings['passwords']['change']['enabled'] ?? null, 'passwords.change.enabled', true);
    }

    public function rehashesPasswordsOnLogin(): bool
    {
        return $this->flag($this->settings['passwords']['rehash_on_login'] ?? null, 'passwords.rehash_on_login', true);
    }

    public function passwordMinLength(): int
    {
        return $this->integer($this->settings['passwords']['policy']['min'] ?? null, 'passwords.policy.min', 10);
    }

    public function passwordMaxLength(): int
    {
        return $this->integer($this->settings['passwords']['policy']['max'] ?? null, 'passwords.policy.max', 128, min: $this->passwordMinLength());
    }

    public function passwordRequiresLetters(): bool
    {
        return $this->flag($this->settings['passwords']['policy']['letters'] ?? null, 'passwords.policy.letters', false);
    }

    public function passwordRequiresMixedCase(): bool
    {
        return $this->flag($this->settings['passwords']['policy']['mixed_case'] ?? null, 'passwords.policy.mixed_case', false);
    }

    public function passwordRequiresNumbers(): bool
    {
        return $this->flag($this->settings['passwords']['policy']['numbers'] ?? null, 'passwords.policy.numbers', false);
    }

    public function passwordRequiresSymbols(): bool
    {
        return $this->flag($this->settings['passwords']['policy']['symbols'] ?? null, 'passwords.policy.symbols', false);
    }

    public function passwordMustNotContainIdentifier(): bool
    {
        return $this->flag($this->settings['passwords']['policy']['not_identifier'] ?? null, 'passwords.policy.not_identifier', true);
    }

    public function breachCheckEnabled(): bool
    {
        return $this->flag($this->settings['passwords']['policy']['uncompromised']['enabled'] ?? null, 'passwords.policy.uncompromised.enabled', false);
    }

    public function breachThreshold(): int
    {
        return $this->integer($this->settings['passwords']['policy']['uncompromised']['threshold'] ?? null, 'passwords.policy.uncompromised.threshold', 0, min: 0);
    }

    public function breachCheckTimeout(): int
    {
        return $this->integer($this->settings['passwords']['policy']['uncompromised']['timeout'] ?? null, 'passwords.policy.uncompromised.timeout', 3);
    }

    public function breachCheckFailsClosed(): bool
    {
        return $this->flag($this->settings['passwords']['policy']['uncompromised']['fail_closed'] ?? null, 'passwords.policy.uncompromised.fail_closed', false);
    }

    // ── Throttling & lockout ─────────────────────────────────────────────

    public function throttle(ThrottleKind $kind): ThrottleLimit
    {
        return match ($kind) {
            ThrottleKind::Login => $this->limit('login', $this->settings['throttle']['login']['max'] ?? null, $this->settings['throttle']['login']['decay'] ?? null, 5, 60),
            ThrottleKind::LoginIp => $this->limit('login_ip', $this->settings['throttle']['login_ip']['max'] ?? null, $this->settings['throttle']['login_ip']['decay'] ?? null, 50, 600),
            ThrottleKind::LoginAccount => $this->limit('login_account', $this->settings['throttle']['login_account']['max'] ?? null, $this->settings['throttle']['login_account']['decay'] ?? null, 20, 3_600),
            ThrottleKind::EmailRequest => $this->limit('email_request', $this->settings['throttle']['email_request']['max'] ?? null, $this->settings['throttle']['email_request']['decay'] ?? null, 3, 600),
            ThrottleKind::EmailRequestIp => $this->limit('email_request_ip', $this->settings['throttle']['email_request_ip']['max'] ?? null, $this->settings['throttle']['email_request_ip']['decay'] ?? null, 20, 600),
            ThrottleKind::EmailRequestAccount => $this->limit('email_request_account', $this->settings['throttle']['email_request_account']['max'] ?? null, $this->settings['throttle']['email_request_account']['decay'] ?? null, 10, 3_600),
            ThrottleKind::Refresh => $this->limit('refresh', $this->settings['throttle']['refresh']['max'] ?? null, $this->settings['throttle']['refresh']['decay'] ?? null, 30, 60),
            ThrottleKind::Registration => $this->limit('registration', $this->settings['throttle']['registration']['max'] ?? null, $this->settings['throttle']['registration']['decay'] ?? null, 5, 3_600),
            ThrottleKind::Verification => $this->limit('verification', $this->settings['throttle']['verification']['max'] ?? null, $this->settings['throttle']['verification']['decay'] ?? null, 5, 600),
            ThrottleKind::Reauthentication => $this->limit('reauthentication', $this->settings['throttle']['reauthentication']['max'] ?? null, $this->settings['throttle']['reauthentication']['decay'] ?? null, 5, 300),
        };
    }

    public function lockoutEnabled(): bool
    {
        return $this->flag($this->settings['lockout']['enabled'] ?? null, 'lockout.enabled', false);
    }

    public function lockoutThreshold(): int
    {
        return $this->integer($this->settings['lockout']['threshold'] ?? null, 'lockout.threshold', 10, max: 1_000_000);
    }

    public function lockoutDuration(): int
    {
        return $this->integer($this->settings['lockout']['duration'] ?? null, 'lockout.duration', 900);
    }

    public function passwordResetUnlocks(): bool
    {
        return $this->flag($this->settings['lockout']['reset_unlocks'] ?? null, 'lockout.reset_unlocks', true);
    }

    // ── Re-authentication ────────────────────────────────────────────────

    public function reauthenticationTimeout(): int
    {
        return $this->integer($this->settings['reauthentication']['timeout'] ?? null, 'reauthentication.timeout', 900);
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
        return $this->flag($this->settings['reauthentication']['require_second_factor_when_enrolled'] ?? null, 'reauthentication.require_second_factor_when_enrolled', true);
    }

    public function freshLoginCountsAsReauthentication(): bool
    {
        return $this->flag($this->settings['reauthentication']['fresh_login_counts'] ?? null, 'reauthentication.fresh_login_counts', true);
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
        return $this->flag($this->settings['activity']['enabled'] ?? null, 'activity.enabled', true);
    }

    public function identifierStorage(): IdentifierStorage
    {
        return $this->enum(IdentifierStorage::class, $this->settings['activity']['store_identifier'] ?? null, 'activity.store_identifier', IdentifierStorage::Plain);
    }

    public function activityRetentionDays(): int
    {
        return $this->integer($this->settings['activity']['retention_days'] ?? null, 'activity.retention_days', 90);
    }

    public function newDeviceDetectionEnabled(): bool
    {
        return $this->flag($this->settings['activity']['new_device']['enabled'] ?? null, 'activity.new_device.enabled', true);
    }

    public function newDeviceHeader(): string
    {
        return $this->requiredString($this->settings['activity']['new_device']['header'] ?? null, 'activity.new_device.header', 'X-Device-Id');
    }

    public function newDeviceSkipsFirstLogin(): bool
    {
        return $this->flag($this->settings['activity']['new_device']['skip_first_login'] ?? null, 'activity.new_device.skip_first_login', true);
    }

    public function riskAssessor(): ?string
    {
        return $this->optionalString($this->settings['risk']['assessor'] ?? null, 'risk.assessor');
    }

    public function riskReaction(RiskLevel $level): RiskReaction
    {
        return match ($level) {
            RiskLevel::Low => RiskReaction::Allow,
            RiskLevel::Elevated => $this->enum(RiskReaction::class, $this->settings['risk']['reactions']['elevated'] ?? null, 'risk.reactions.elevated', RiskReaction::Notify),
            RiskLevel::High => $this->enum(RiskReaction::class, $this->settings['risk']['reactions']['high'] ?? null, 'risk.reactions.high', RiskReaction::RequireSecondFactor),
        };
    }

    public function riskDenialIsUniform(): bool
    {
        return $this->choice($this->settings['risk']['deny_response'] ?? null, 'risk.deny_response', 'uniform', 'explicit', true);
    }

    // ── Locale ───────────────────────────────────────────────────────────

    public function localeHeader(): ?string
    {
        return $this->optionalString($this->settings['locale']['header'] ?? null, 'locale.header');
    }

    /**
     * @return list<string>
     */
    public function supportedLocales(): array
    {
        $supported = $this->stringList($this->settings['locale']['supported'] ?? null, 'locale.supported');

        if ($supported !== []) {
            return $supported;
        }

        $default = config('app.locale');

        return [is_string($default) && $default !== '' ? $default : 'en'];
    }

    public function storesLocaleOnRegistration(): bool
    {
        return $this->flag($this->settings['locale']['store_on_registration'] ?? null, 'locale.store_on_registration', true);
    }

    public function fillsLocaleOnLogin(): bool
    {
        return $this->flag($this->settings['locale']['fill_on_login'] ?? null, 'locale.fill_on_login', true);
    }

    public function timezonesEnabled(): bool
    {
        return $this->flag($this->settings['locale']['timezone'] ?? null, 'locale.timezone', true);
    }

    // ── Notifications ────────────────────────────────────────────────────

    public function notificationDelivery(): NotificationDelivery
    {
        return $this->enum(NotificationDelivery::class, $this->settings['notifications']['delivery'] ?? null, 'notifications.delivery', NotificationDelivery::AfterResponse);
    }

    public function notificationConnection(): ?string
    {
        return $this->optionalString($this->settings['notifications']['connection'] ?? null, 'notifications.connection');
    }

    public function notificationQueue(): ?string
    {
        return $this->optionalString($this->settings['notifications']['queue'] ?? null, 'notifications.queue');
    }

    /**
     * The configured class for a notification, or null when the host disabled it. A type
     * added after 1.0 falls back to its shipped class when its key is ABSENT — a published
     * config replaces `defaults` whole and predates it — and is off only when set to null.
     */
    public function notificationClass(NotificationType $type): ?string
    {
        $classes = $this->settings['notifications']['classes'] ?? null;
        $classes = is_array($classes) ? $classes : [];

        return $this->optionalString(match ($type) {
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
            NotificationType::SignInBlocked => array_key_exists('sign_in_blocked', $classes) ? ($this->settings['notifications']['classes']['sign_in_blocked'] ?? null) : SignInBlockedNotification::class,
            NotificationType::UnusualSignIn => array_key_exists('unusual_sign_in', $classes) ? ($this->settings['notifications']['classes']['unusual_sign_in'] ?? null) : UnusualSignInNotification::class,
        }, 'notifications.classes.'.$type->value);
    }

    public function frontendUrl(): string
    {
        $url = $this->optionalString($this->settings['notifications']['frontend_url'] ?? null, 'notifications.frontend_url') ?? $this->appUrl();

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

        // Not set (absent, null or blank — an empty env var): the shipped default's path,
        // never a guessed one. Not a string, it throws.
        $path = match ($kind) {
            UrlKind::MagicLink => 'magic-link',
            UrlKind::VerifyEmail => 'verify-email',
            UrlKind::ResetPassword => 'reset-password',
            UrlKind::ConfirmEmailChange => 'confirm-email',
            UrlKind::Invitation => 'invitation',
        };

        return $this->requiredString($template, 'notifications.urls.'.$kind->value, '{frontend}/auth/'.$path.'?guard={guard}#token={token}');
    }

    // ── Routes & resources ───────────────────────────────────────────────

    public function routesEnabled(): bool
    {
        return $this->flag($this->settings['routes']['enabled'] ?? null, 'routes.enabled', false);
    }

    public function routePrefix(): string
    {
        $prefix = $this->requiredString($this->settings['routes']['prefix'] ?? null, 'routes.prefix', '{guard}/auth');

        return trim(str_replace('{guard}', $this->name, $prefix), '/');
    }

    public function routeName(): string
    {
        $name = $this->requiredString($this->settings['routes']['name'] ?? null, 'routes.name', 'authentication.{guard}.');

        return str_replace('{guard}', $this->name, $name);
    }

    /**
     * @return list<string>
     */
    public function routeMiddleware(): array
    {
        return $this->stringList($this->settings['routes']['middleware'] ?? null, 'routes.middleware');
    }

    /**
     * @return list<string>
     */
    public function authenticatedRouteMiddleware(): array
    {
        return $this->stringList($this->settings['routes']['authenticated_middleware'] ?? null, 'routes.authenticated_middleware');
    }

    public function invitationManagementRoutes(): bool
    {
        return $this->flag($this->settings['routes']['invitations_management'] ?? null, 'routes.invitations_management', false);
    }

    public function accountResource(): ?string
    {
        return $this->optionalString($this->settings['resources']['account'] ?? null, 'resources.account');
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /**
     * An enum leaf: not set (absent, null or blank — an empty env var) is the shipped
     * default; an unknown value throws naming the key rather than reading as the default.
     *
     * @template TEnum of BackedEnum
     *
     * @param  class-string<TEnum>  $enum
     * @param  TEnum  $default
     * @return TEnum
     */
    private function enum(string $enum, mixed $value, string $key, BackedEnum $default): BackedEnum
    {
        if ($value instanceof $enum) {
            return $value;
        }

        if (self::notSet($value)) {
            return $default;
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

        foreach ($this->stringList($values, $key) as $value) {
            $case = $enum::tryFrom($value) ?? throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.{$key} contains the unknown value [{$value}].");

            if (! in_array($case, $cases, true)) {
                $cases[] = $case;
            }
        }

        return $cases;
    }

    /**
     * A list leaf: not set (absent, null or blank) is `[]`; anything but a list of non-empty
     * strings throws naming the key — a stray entry is never silently dropped (dropping one
     * from `routes.authenticated_middleware` would silently remove a middleware).
     *
     * @return list<string>
     *
     * @throws AuthenticationMisconfigured
     */
    private function stringList(mixed $value, string $key): array
    {
        if (self::notSet($value)) {
            return [];
        }

        if (! is_array($value) || ! array_is_list($value)) {
            throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.{$key} must be a list of strings.");
        }

        foreach ($value as $item) {
            if (! is_string($item) || trim($item) === '') {
                throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.{$key} must contain only non-empty strings.");
            }
        }

        return $value;
    }

    /**
     * A switch read the way env values arrive: env() only converts "true"/"false", so
     * "1"/"on"/"yes" and "0"/"off"/"no" are parsed as booleans here rather than cast (a
     * `(bool) 'off'` is true). Not set (absent, null or blank) is the default; anything
     * else throws, naming the guard's key, so a typo can never quietly flip a switch to
     * its default.
     *
     * @param  string  $key  the leaf's path under the guard, matching the offset chain read
     *
     * @throws AuthenticationMisconfigured
     */
    private function flag(mixed $value, string $key, bool $default): bool
    {
        $key = "authentication.guards.{$this->name}.{$key}";

        try {
            return Config::for([$key => $value])->boolean($key, $default);
        } catch (InvalidConfigurationException $e) {
            throw AuthenticationMisconfigured::because($e->getMessage());
        }
    }

    /**
     * A two-way string switch (`identifier.normalize`, `risk.deny_response`). Not set
     * (absent, null or blank) is the default; an unknown spelling throws rather than
     * silently picking a side.
     *
     * @throws AuthenticationMisconfigured
     */
    private function choice(mixed $value, string $key, string $on, string $off, bool $default): bool
    {
        if (self::notSet($value)) {
            return $default;
        }

        return match ($value) {
            $on => true,
            $off => false,
            default => throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.{$key} must be {$on} or {$off}."),
        };
    }

    /**
     * An optional string leaf: absent, null or blank (an empty env var) reads as unset; a
     * value that is not a string throws naming the key instead of silently reading as unset.
     *
     * @throws AuthenticationMisconfigured
     */
    private function optionalString(mixed $value, string $key): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.{$key} must be a string or null.");
        }

        return trim($value) === '' ? null : $value;
    }

    /**
     * A string leaf with a default: not set (absent, null or blank — an empty env var) is
     * the default; a value that is not a string throws naming the key.
     *
     * @throws AuthenticationMisconfigured
     */
    private function requiredString(mixed $value, string $key, string $default): string
    {
        if (self::notSet($value)) {
            return $default;
        }

        if (! is_string($value)) {
            throw AuthenticationMisconfigured::because("authentication.guards.{$this->name}.{$key} must be a string.");
        }

        return $value;
    }

    /**
     * Absent, null or blank (`''` or whitespace — what a host's `KEY=` puts in config):
     * the leaf is not set, so its default applies.
     */
    private static function notSet(mixed $value): bool
    {
        return $value === null || (is_string($value) && trim($value) === '');
    }

    /**
     * An integer leaf: not set (absent, null or blank) is the default; otherwise an int or a
     * canonical integer string (env values arrive as strings) within the bounds — `$min` 1
     * unless the leaf gives 0 a meaning. `'five'`, `'1.5'` or an out-of-range value throws
     * naming the guard's key: a junk TTL never reads as the default, and a 0 that would
     * disable a limit never slips through.
     *
     * @param  string  $key  the leaf's path under the guard, matching the offset chain read
     *
     * @throws AuthenticationMisconfigured
     */
    private function integer(mixed $value, string $key, int $default, ?int $min = 1, ?int $max = null): int
    {
        $key = "authentication.guards.{$this->name}.{$key}";

        try {
            return Config::for([$key => $value])->integer($key, $default, $min, $max);
        } catch (InvalidConfigurationException $e) {
            throw AuthenticationMisconfigured::because($e->getMessage());
        }
    }

    private function limit(string $kind, mixed $max, mixed $decay, int $defaultMax, int $defaultDecay): ThrottleLimit
    {
        return new ThrottleLimit(
            $this->integer($max, "throttle.{$kind}.max", $defaultMax),
            $this->integer($decay, "throttle.{$kind}.decay", $defaultDecay),
        );
    }
}
