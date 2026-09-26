<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Registration;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Validation\ValidationException;
use RoundlyConsulting\Auth\Actions\Activity\RecordLoginActivity;
use RoundlyConsulting\Auth\Actions\Email\SendEmailVerification;
use RoundlyConsulting\Auth\Actions\Login\CompleteFirstFactor;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\CreatesAccounts;
use RoundlyConsulting\Auth\DataTransferObjects\LoginActivityData;
use RoundlyConsulting\Auth\DataTransferObjects\NewAccountData;
use RoundlyConsulting\Auth\DataTransferObjects\NotificationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationData;
use RoundlyConsulting\Auth\DataTransferObjects\RegistrationResult;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Enums\AuthMethodReference;
use RoundlyConsulting\Auth\Enums\EmailVerificationMode;
use RoundlyConsulting\Auth\Enums\LoginMethod;
use RoundlyConsulting\Auth\Enums\NotificationType;
use RoundlyConsulting\Auth\Enums\RegistrationMode;
use RoundlyConsulting\Auth\Enums\RegistrationStatus;
use RoundlyConsulting\Auth\Enums\ThrottleKind;
use RoundlyConsulting\Auth\Events\AccountRegistered;
use RoundlyConsulting\Auth\Exceptions\EnrolmentRequired;
use RoundlyConsulting\Auth\Exceptions\InvitationRequired;
use RoundlyConsulting\Auth\Exceptions\RegistrationClosed;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\NotificationDispatcher;
use RoundlyConsulting\Auth\Support\RegistrationValidator;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Auth\Support\Throttle;

/**
 * Open registration. When the answer would not issue tokens anyway (verification
 * required for login, or `login_after = false`), an address already in use gets an
 * "account exists" notice and the caller the very same status a new account would —
 * registration cannot probe for accounts — including through its timing: the taken
 * address pays the same password hash a new account's creation does. When tokens WOULD
 * be issued immediately the difference is observable regardless, so a plain "email
 * taken" error is returned.
 */
final readonly class RegisterAccount
{
    public function __construct(
        private GuardRegistry $guards,
        private Container $container,
        private Throttle $throttle,
        private RegistrationValidator $validator,
        private SendEmailVerification $sendVerification,
        private CompleteFirstFactor $completeFirstFactor,
        private NotificationDispatcher $notifications,
        private RecordLoginActivity $recordActivity,
        private SecretHasher $hasher,
        private Hasher $passwords,
    ) {}

    public function execute(string $guard, RegistrationData $data): RegistrationResult
    {
        $config = $this->guards->get($guard);

        match ($config->registrationMode()) {
            RegistrationMode::Closed => throw new RegistrationClosed,
            RegistrationMode::InviteOnly => throw new InvitationRequired,
            RegistrationMode::Open => null,
        };

        $this->throttle->attempt($config, [ThrottleKind::Registration], null, $data->context, ActivityType::Registration);

        $accounts = new AccountRepository($config);
        $email = $accounts->normalizeEmail($data->email);
        $attributes = $this->validator->validate($config, $email, $data->password, $data->attributes);

        if ($accounts->emailTaken($email)) {
            return $this->existing($config, $email, $data, hashed: false);
        }

        try {
            $account = AccountModels::of($accounts->newModel())->getConnection()->transaction(fn (): Account => $this->creator($config)->create($config, new NewAccountData(
                email: $email,
                password: $data->password,
                locale: $config->storesLocaleOnRegistration() ? $data->context->locale : null,
                timezone: $data->context->timezone,
                emailVerified: false,
                attributes: $attributes,
            )));
        } catch (UniqueConstraintViolationException) {
            // Lost the insert race: the creator already hashed the password.
            return $this->existing($config, $email, $data, hashed: true);
        }

        event(new AccountRegistered($guard, $account, LoginMethod::Registration));

        $this->recordActivity->execute(new LoginActivityData(
            guard: $guard,
            type: ActivityType::Registration,
            outcome: ActivityOutcome::Succeeded,
            context: $data->context,
            method: LoginMethod::Registration->value,
            account: $account,
            identifier: $email,
        ));

        if ($config->verificationMode() !== EmailVerificationMode::Off) {
            $this->sendVerification->execute($guard, $account, $data->context);
        }

        if ($this->enumerationSafe($config)) {
            return new RegistrationResult($this->safeStatus($config));
        }

        try {
            $login = $this->completeFirstFactor->execute($config, $account, LoginMethod::Registration, $data->context, $data->password === null ? [] : [AuthMethodReference::Pwd]);
        } catch (EnrolmentRequired) {
            // A fresh account is unverified; it enrols on its first login after verifying.
            return new RegistrationResult(RegistrationStatus::VerificationRequired);
        }

        return new RegistrationResult(RegistrationStatus::Authenticated, $login);
    }

    private function existing(GuardConfig $guard, string $email, RegistrationData $data, bool $hashed): RegistrationResult
    {
        if (! $this->enumerationSafe($guard)) {
            throw ValidationException::withMessages(['email' => __('authentication::validation.email_taken')]);
        }

        // Equal cost: creating the account would have hashed the password (bcrypt is the
        // dominant term of the response time — skipping it is a timing oracle).
        if (! $hashed && $data->password !== null) {
            $this->passwords->make($data->password);
        }

        if ($this->throttle->cooldown("authentication:{$guard->name()}:account-exists:".$this->hasher->identifier($guard->name(), $email), 600)) {
            $this->notifications->sendTo($guard, NotificationType::AccountExists, $email, new NotificationData($guard->name()), $data->context->locale);
        }

        return new RegistrationResult($this->safeStatus($guard));
    }

    private function enumerationSafe(GuardConfig $guard): bool
    {
        return $guard->verificationMode() === EmailVerificationMode::RequiredForLogin || ! $guard->loginAfterRegistration();
    }

    private function safeStatus(GuardConfig $guard): RegistrationStatus
    {
        return $guard->verificationMode() === EmailVerificationMode::RequiredForLogin
            ? RegistrationStatus::VerificationRequired
            : RegistrationStatus::Accepted;
    }

    private function creator(GuardConfig $guard): CreatesAccounts
    {
        $class = $guard->accountCreator() ?? CreateAccount::class;
        $creator = $this->container->make($class);

        return $creator instanceof CreatesAccounts ? $creator : $this->container->make(CreateAccount::class);
    }
}
