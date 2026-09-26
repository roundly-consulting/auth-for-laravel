<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Passwords;

use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Actions\Sessions\InvalidateAccountTokens;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ChangePasswordData;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\InvalidationReason;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\SensitiveAction;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\PasswordChanged;
use RoundlyConsulting\Auth\Exceptions\LoginMethodDisabled;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\PasswordWriter;
use RoundlyConsulting\Auth\Support\SensitiveActionGate;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * Changes the signed-in account's password: the current password is required when
 * there is one (throttled like a re-authentication — a stolen token must not become a
 * password-guessing oracle); an account without one is SETTING a password and needs a
 * recent re-authentication instead while `set_password` is in the guard's
 * `reauthentication.required_for` (the default). The new password must differ and pass
 * the policy. Returns the pair re-issued to the calling device under
 * `invalidation.password_changed = others` (the default); null for `none` (tokens
 * unchanged) or `all`.
 */
final readonly class ChangePassword
{
    public function __construct(
        private GuardRegistry $guards,
        private Throttle $throttle,
        private VerifyPassword $verifyPassword,
        private ValidatePasswordPolicy $policy,
        private SensitiveActionGate $gate,
        private InvalidateAccountTokens $invalidate,
        private NotificationDispatcher $notifications,
    ) {}

    public function execute(string $guard, Account $account, ChangePasswordData $data): ?TokenPair
    {
        $config = $this->guards->get($guard);

        if (! $config->passwordChangeEnabled()) {
            throw new LoginMethodDisabled;
        }

        $sessionKey = $data->current->sessionKey();
        $this->throttle->ensure($config, [ThrottleKind::Reauthentication], $sessionKey, $data->context, ActivityType::Reauthentication);

        if ($account->hasPassword()) {
            if (! $this->verifyPassword->execute($account, (string) $data->currentPassword)) {
                $this->throttle->hit($config, [ThrottleKind::Reauthentication], $sessionKey, $data->context->ipAddress);

                throw ValidationException::withMessages(['current_password' => __('authentication::validation.password.current_incorrect')]);
            }

            if ($this->verifyPassword->execute($account, $data->newPassword)) {
                throw ValidationException::withMessages(['password' => __('authentication::validation.password.reused')]);
            }
        } else {
            $this->gate->check($config, SensitiveAction::SetPassword, $data->current, $account);
        }

        $this->policy->execute($config, $data->newPassword, $account);

        PasswordWriter::write($account, $data->newPassword);

        $tokens = $this->invalidate->execute($config, $account, InvalidationReason::PasswordChanged, $data->current, $data->context)->tokens;

        event(new PasswordChanged($guard, $account));
        $this->notifications->send($config, NotificationType::PasswordChanged, $account, new NotificationData($guard));

        return $tokens;
    }
}
