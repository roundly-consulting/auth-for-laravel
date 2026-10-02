<?php

declare(strict_types=1);

use RoundlyConsulting\Auth\Actions\Challenges\ResolveRequiredSteps;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\RiskReaction;
use RoundlyConsulting\Auth\Exceptions\LoginDenied;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\User;

/**
 * Every worked example of the policy table plus one row per remaining branch. The count
 * is pinned below so a deleted row reds.
 *
 * Row: [guard settings, account {totp, passkey, verified}, method, risk, expected steps]
 * where a step is written `step{method,method}`.
 */
/**
 * @return array<string, array<int, mixed>>
 */
function policyRows(): array
{
    return [
        'T=optional S=allowed, totp+passkey, password' => [['two_factor.mode' => 'optional', 'passkeys.second_factor' => 'allowed'], ['totp' => true, 'passkey' => true], LoginMethod::Password, RiskReaction::Allow, ['second_factor{totp,recovery_code,passkey}']],
        'T=optional S=required_when_enrolled, passkey, password' => [['passkeys.second_factor' => 'required_when_enrolled'], ['passkey' => true], LoginMethod::Password, RiskReaction::Allow, ['passkey{passkey}']],
        'T=optional S=required, no passkey, password' => [['passkeys.second_factor' => 'required'], [], LoginMethod::Password, RiskReaction::Allow, ['enrol_passkey{passkey_enrolment}']],
        'T=required S=off, no totp, password' => [['two_factor.mode' => 'required', 'passkeys.second_factor' => 'off'], [], LoginMethod::Password, RiskReaction::Allow, ['enrol_two_factor{totp_enrolment}']],
        'T=required S=allowed, passkey, magic link' => [['two_factor.mode' => 'required'], ['passkey' => true], LoginMethod::MagicLink, RiskReaction::Allow, ['second_factor{passkey}']],
        'T=required S=allowed Q=false, passkey, password' => [['two_factor.mode' => 'required', 'two_factor.passkey_satisfies_required' => false], ['passkey' => true], LoginMethod::Password, RiskReaction::Allow, ['enrol_two_factor{totp_enrolment}']],
        'T=required S=required Q=false, totp+passkey, password' => [['two_factor.mode' => 'required', 'passkeys.second_factor' => 'required', 'two_factor.passkey_satisfies_required' => false], ['totp' => true, 'passkey' => true], LoginMethod::Password, RiskReaction::Allow, ['passkey{passkey}', 'second_factor{totp,recovery_code}']],
        'T=required S=required Q=true, nothing, password' => [['two_factor.mode' => 'required', 'passkeys.second_factor' => 'required'], [], LoginMethod::Password, RiskReaction::Allow, ['enrol_passkey{passkey_enrolment}']],
        'T=required Y=true, anything, passkey' => [['two_factor.mode' => 'required'], ['totp' => true, 'passkey' => true], LoginMethod::Passkey, RiskReaction::Allow, []],
        'T=required Y=false, no totp, passkey' => [['two_factor.mode' => 'required', 'passkeys.satisfies_mfa' => false], ['passkey' => true], LoginMethod::Passkey, RiskReaction::Allow, ['enrol_two_factor{totp_enrolment}']],
        'T=optional Y=false, totp, passkey' => [['passkeys.satisfies_mfa' => false], ['totp' => true, 'passkey' => true], LoginMethod::Passkey, RiskReaction::Allow, ['second_factor{totp,recovery_code}']],
        'T=off P=required, no passkey, email otp' => [['two_factor.mode' => 'off', 'passkeys.mode' => 'required'], [], LoginMethod::EmailOtp, RiskReaction::Allow, ['enrol_passkey{passkey_enrolment}']],
        'T=optional E=false, totp, magic link' => [['two_factor.after_email_login' => false], ['totp' => true], LoginMethod::MagicLink, RiskReaction::Allow, []],
        'T=optional E=false, totp, password reset' => [['two_factor.after_email_login' => false], ['totp' => true], LoginMethod::PasswordReset, RiskReaction::Allow, ['second_factor{totp,recovery_code}']],
        'T=required E=true, new account, registration' => [['two_factor.mode' => 'required'], [], LoginMethod::Registration, RiskReaction::Allow, ['enrol_two_factor{totp_enrolment}']],
        'T=optional risk=high, totp, password' => [[], ['totp' => true], LoginMethod::Password, RiskReaction::RequireSecondFactor, ['second_factor{totp,recovery_code}']],
        // Remaining branches.
        'T=optional, nothing, password' => [[], [], LoginMethod::Password, RiskReaction::Allow, []],
        'T=optional S=allowed, passkey only, password' => [[], ['passkey' => true], LoginMethod::Password, RiskReaction::Allow, []],
        'T=optional risk=high, passkey only, password' => [[], ['passkey' => true], LoginMethod::Password, RiskReaction::RequireSecondFactor, ['second_factor{passkey}']],
        'T=optional S=off risk=high, totp+passkey, password' => [['passkeys.second_factor' => 'off'], ['totp' => true, 'passkey' => true], LoginMethod::Password, RiskReaction::RequireSecondFactor, ['second_factor{totp,recovery_code}']],
        'T=required R=true Y=true, no totp, passkey' => [['two_factor.mode' => 'required', 'two_factor.required_with_passkey' => true], ['passkey' => true], LoginMethod::Passkey, RiskReaction::Allow, ['enrol_two_factor{totp_enrolment}']],
        'T=off, totp columns set, password (2FA ignored)' => [['two_factor.mode' => 'off'], ['totp' => true], LoginMethod::Password, RiskReaction::Allow, []],
        'P=required, passkey present, password' => [['passkeys.mode' => 'required'], ['passkey' => true], LoginMethod::Password, RiskReaction::Allow, []],
        'T=required S=required_when_enrolled Q=false, totp+passkey, password' => [['two_factor.mode' => 'required', 'passkeys.second_factor' => 'required_when_enrolled', 'two_factor.passkey_satisfies_required' => false], ['totp' => true, 'passkey' => true], LoginMethod::Password, RiskReaction::Allow, ['passkey{passkey}', 'second_factor{totp,recovery_code}']],
        'T=required S=required Q=false, passkey no totp, password' => [['two_factor.mode' => 'required', 'passkeys.second_factor' => 'required', 'two_factor.passkey_satisfies_required' => false], ['passkey' => true], LoginMethod::Password, RiskReaction::Allow, ['passkey{passkey}', 'enrol_two_factor{totp_enrolment}']],
        'T=optional S=required P=required, nothing, password (one enrol_passkey)' => [['passkeys.second_factor' => 'required', 'passkeys.mode' => 'required'], [], LoginMethod::Password, RiskReaction::Allow, ['enrol_passkey{passkey_enrolment}']],
        'T=required E=true, totp, invitation' => [['two_factor.mode' => 'required'], ['totp' => true], LoginMethod::Invitation, RiskReaction::Allow, ['second_factor{totp,recovery_code}']],
        // Registration proves no mailbox: E=false does not exempt it.
        'T=required E=false, new account, registration' => [['two_factor.mode' => 'required', 'two_factor.after_email_login' => false], [], LoginMethod::Registration, RiskReaction::Allow, ['enrol_two_factor{totp_enrolment}']],
    ];
}

dataset('policy', policyRows());

it('resolves the required steps', function (array $settings, array $has, LoginMethod $method, RiskReaction $reaction, array $expected): void {
    $this->configureGuard('users', $settings);
    $user = User::factory()->create();

    if ($has['totp'] ?? false) {
        enableTotp($user);
    }

    if ($has['passkey'] ?? false) {
        addPasskey($user);
    }

    $steps = app(ResolveRequiredSteps::class)->execute(app(GuardRegistry::class)->get('users'), $user->fresh(), $method, $reaction);

    expect(array_map(
        static fn (ChallengeRequirement $requirement): string => $requirement->step->value.'{'.implode(',', array_map(fn ($m) => $m->value, $requirement->methods)).'}',
        $steps,
    ))->toBe($expected);
})->with('policy');

it('pins the number of policy rows', function (): void {
    expect(policyRows())->toHaveCount(28);
});

it('denies a risk step-up the account cannot satisfy', function (): void {
    $user = User::factory()->create();

    app(ResolveRequiredSteps::class)->execute(app(GuardRegistry::class)->get('users'), $user, LoginMethod::Password, RiskReaction::RequireSecondFactor);
})->throws(LoginDenied::class);
