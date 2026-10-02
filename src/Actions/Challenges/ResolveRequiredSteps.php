<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Challenges;

use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChallengeRequirement;
use RoundlyConsulting\Auth\Enums\ChallengeStep;
use RoundlyConsulting\Auth\Enums\FactorMethod;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\PasskeyMode;
use RoundlyConsulting\Auth\Enums\PasskeySecondFactor;
use RoundlyConsulting\Auth\Enums\RiskReaction;
use RoundlyConsulting\Auth\Enums\TwoFactorMode;
use RoundlyConsulting\Auth\Exceptions\LoginDenied;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\ReauthenticationMethods;

/**
 * The policy table: which steps a login still needs after its first factor, given the
 * primary method M, the guard's two-factor mode T, passkey mode P, passkey second-factor
 * rule S, `passkeys.satisfies_mfa` Y, `two_factor.after_email_login` E,
 * `two_factor.required_with_passkey` R, `two_factor.passkey_satisfies_required` Q, what
 * the account has enrolled, and the risk reaction.
 *
 * Verification steps always precede enrolment steps. A password reset is never exempt
 * from an enrolled second factor (a mailbox compromise must not bypass 2FA), and
 * registration never counts as an email-possession primary (it proves no mailbox).
 *
 * The risk step-up applies to EVERY primary: E = false exempts email logins from the
 * two-factor policy, not from a `require_second_factor` reaction. A passkey primary that
 * counts as MFA (Y) already is the step-up; one that does not must add TOTP — the same
 * passkey cannot step itself up.
 *
 * @internal a login-pipeline step (`CompleteFirstFactor`).
 */
final class ResolveRequiredSteps
{
    /**
     * @return list<ChallengeRequirement>
     *
     * @throws LoginDenied when a risk step-up is required but the account has no factor to step up with
     */
    public function execute(GuardConfig $guard, Account $account, LoginMethod $method, RiskReaction $reaction = RiskReaction::Allow): array
    {
        $passkeys = $guard->passkeyMode();
        $secondFactor = $passkeys === PasskeyMode::Off ? PasskeySecondFactor::Off : $guard->passkeySecondFactor();
        $hasTotp = ReauthenticationMethods::hasTotp($guard, $account);
        $hasPasskeys = ReauthenticationMethods::hasPasskeys($guard, $account);

        $steps = $this->policySteps($guard, $method, $secondFactor, $hasTotp, $hasPasskeys);

        // Risk step-up needs a VERIFICATION step — an enrolment proves nothing about this login.
        if ($reaction === RiskReaction::RequireSecondFactor
            && ! ($method === LoginMethod::Passkey && $guard->passkeySatisfiesMfa())
            && ! $this->contains($steps, ChallengeStep::SecondFactor)
            && ! $this->contains($steps, ChallengeStep::Passkey)) {
            $available = [
                ...($hasTotp ? [FactorMethod::Totp, FactorMethod::RecoveryCode] : []),
                ...($hasPasskeys && $secondFactor !== PasskeySecondFactor::Off && $method !== LoginMethod::Passkey ? [FactorMethod::Passkey] : []),
            ];

            if ($available === []) {
                throw new LoginDenied;
            }

            array_unshift($steps, new ChallengeRequirement(ChallengeStep::SecondFactor, $available));
        }

        return $this->verificationFirst($steps);
    }

    /**
     * The steps the two-factor and passkey policy demands, before any risk step-up.
     *
     * @return list<ChallengeRequirement>
     */
    private function policySteps(GuardConfig $guard, LoginMethod $method, PasskeySecondFactor $secondFactor, bool $hasTotp, bool $hasPasskeys): array
    {
        $twoFactor = $guard->twoFactorMode();
        $satisfiesMfa = $guard->passkeySatisfiesMfa();
        $q = $guard->passkeySatisfiesRequiredTwoFactor();

        $totp = new ChallengeRequirement(ChallengeStep::SecondFactor, [FactorMethod::Totp, FactorMethod::RecoveryCode]);
        $enrolTotp = new ChallengeRequirement(ChallengeStep::EnrolTwoFactor, [FactorMethod::TotpEnrolment]);
        $passkey = new ChallengeRequirement(ChallengeStep::Passkey, [FactorMethod::Passkey]);
        $enrolPasskey = new ChallengeRequirement(ChallengeStep::EnrolPasskey, [FactorMethod::PasskeyEnrolment]);

        // 1. Passkey primary (passwordless): a UV passkey already is MFA when Y.
        if ($method === LoginMethod::Passkey) {
            if ($hasTotp && ! $satisfiesMfa) {
                return [$totp];
            }

            if ($twoFactor === TwoFactorMode::Required && ! $hasTotp && (! $satisfiesMfa || $guard->twoFactorRequiredWithPasskey())) {
                return [$enrolTotp];
            }

            return [];
        }

        // 2. Email-possession primaries are exempt only when the host opts out (E = false).
        //    PasswordReset is deliberately absent (D12); Registration proves no mailbox.
        $emailPrimaries = [LoginMethod::MagicLink, LoginMethod::EmailOtp, LoginMethod::Invitation];

        if (in_array($method, $emailPrimaries, true) && ! $guard->twoFactorAfterEmailLogin()) {
            return [];
        }

        // 3. Verification steps.
        $passkeyAlternative = $secondFactor === PasskeySecondFactor::Allowed && $hasPasskeys && ($twoFactor !== TwoFactorMode::Required || $q);
        $totpStillNeeded = $twoFactor === TwoFactorMode::Required && ! $q;
        $steps = [];

        if ($secondFactor === PasskeySecondFactor::Required
            || ($secondFactor === PasskeySecondFactor::RequiredWhenEnrolled && $hasPasskeys)) {
            $steps[] = $hasPasskeys ? $passkey : $enrolPasskey;

            if ($totpStillNeeded) {
                $steps[] = $hasTotp ? $totp : $enrolTotp;
            }
        } elseif ($hasTotp) {
            $steps[] = $passkeyAlternative
                ? new ChallengeRequirement(ChallengeStep::SecondFactor, [FactorMethod::Totp, FactorMethod::RecoveryCode, FactorMethod::Passkey])
                : $totp;
        } elseif ($twoFactor === TwoFactorMode::Required) {
            $steps[] = $passkeyAlternative && $q
                ? new ChallengeRequirement(ChallengeStep::SecondFactor, [FactorMethod::Passkey])
                : $enrolTotp;
        }

        // 4. Enrolment of a mandated passkey.
        if ($guard->passkeyMode() === PasskeyMode::Required && ! $hasPasskeys && ! $this->contains($steps, ChallengeStep::EnrolPasskey)) {
            $steps[] = $enrolPasskey;
        }

        return $steps;
    }

    /**
     * @param  list<ChallengeRequirement>  $steps
     */
    private function contains(array $steps, ChallengeStep $step): bool
    {
        foreach ($steps as $requirement) {
            if ($requirement->step === $step) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<ChallengeRequirement>  $steps
     * @return list<ChallengeRequirement>
     */
    private function verificationFirst(array $steps): array
    {
        return [
            ...array_values(array_filter($steps, static fn (ChallengeRequirement $requirement): bool => ! $requirement->step->isEnrolment())),
            ...array_values(array_filter($steps, static fn (ChallengeRequirement $requirement): bool => $requirement->step->isEnrolment())),
        ];
    }
}
