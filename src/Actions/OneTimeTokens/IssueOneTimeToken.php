<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\OneTimeTokens;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Contracts\FingerprintsDevices;
use RoundlyConsulting\Auth\DataTransferObjects\IssuedSecret;
use RoundlyConsulting\Auth\DataTransferObjects\SessionContext;
use RoundlyConsulting\Auth\Enums\OneTimeTokenPurpose;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Models;
use RoundlyConsulting\Auth\Support\SecretHasher;
use RoundlyConsulting\Crypto\Random\Token;

/**
 * Issues an emailed single-use secret: a 64-char link token or a short numeric code
 * (per purpose / verification channel), stored only as a keyed HMAC bound to the guard
 * and purpose (and, for codes, the address). Every earlier usable secret of the same
 * purpose dies — only the newest link or code works. The plaintext is returned once.
 *
 * @internal the one-time-token store behind links and codes.
 */
final readonly class IssueOneTimeToken
{
    public function __construct(
        private SecretHasher $hasher,
        private InvalidateOneTimeTokens $invalidate,
        private FingerprintsDevices $fingerprints,
    ) {}

    /**
     * @param  array<string, mixed>  $payload  e.g. `old_email` for an email change — never a secret
     */
    public function execute(GuardConfig $guard, Account $account, OneTimeTokenPurpose $purpose, string $email, SessionContext $context, array $payload = []): IssuedSecret
    {
        $this->invalidate->execute($guard->name(), $account, $purpose);

        $model = AccountModels::of($account);
        $email = (new AccountRepository($guard))->normalizeEmail($email);
        $usesCode = $guard->usesCode($purpose);
        $token = $usesCode ? null : Token::urlSafe(64);
        $code = $usesCode ? Token::numeric($guard->codeLength($purpose)) : null;
        $sameDevice = $purpose === OneTimeTokenPurpose::MagicLink && $guard->magicLinkSameDevice();

        $record = Models::oneTimeTokens()->create([
            'guard' => $guard->name(),
            'purpose' => $purpose,
            'account_type' => $model->getMorphClass(),
            'account_id' => $model->getKey(),
            'email' => $email,
            'token_hash' => $token === null ? null : $this->hasher->link($guard->name(), $purpose->value, $token),
            'code_hash' => $code === null ? null : $this->hasher->code($guard->name(), $purpose->value, $email, $code),
            'fingerprint_hash' => $sameDevice ? $this->fingerprints->fingerprint($context, $guard) : null,
            'attempts' => 0,
            'max_attempts' => $usesCode ? $guard->codeMaxAttempts($purpose) : 1,
            'payload' => $payload === [] ? null : $payload,
            'ip_address' => $context->ipAddress,
            'user_agent' => $context->userAgent,
            'expires_at' => CarbonImmutable::now()->addSeconds($guard->ttl($purpose)),
        ]);

        return new IssuedSecret($record, $token, $code);
    }
}
