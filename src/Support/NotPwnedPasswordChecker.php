<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Http\Client\Factory as HttpFactory;
use RoundlyConsulting\Auth\Contracts\ChecksBreachedPasswords;
use RoundlyConsulting\Auth\Events\BreachedPasswordCheckFailed;
use RoundlyConsulting\Auth\Exceptions\BreachCheckUnavailable;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use SensitiveParameter;
use Throwable;

/**
 * A k-anonymity range query against Have I Been Pwned: only the first 5 hex chars of
 * the password's SHA-1 leave the server, with `Add-Padding` so the response size says
 * nothing either. Short timeout (`uncompromised.timeout`, default 3 s).
 *
 * Laravel's own `Password::uncompromised()` is not reused: it swallows network errors
 * as "not breached" (fail-open only) with a 30 s default timeout. Here a failure is
 * reported, dispatches {@see BreachedPasswordCheckFailed}, and fails open unless the
 * guard sets `uncompromised.fail_closed`.
 */
final readonly class NotPwnedPasswordChecker implements ChecksBreachedPasswords
{
    public const string ENDPOINT = 'https://api.pwnedpasswords.com/range/';

    public function __construct(private HttpFactory $http) {}

    public function isBreached(#[SensitiveParameter] string $password, GuardConfig $guard): bool
    {
        $hash = strtoupper((new Digest(HashAlgorithm::Sha1))->hex($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        try {
            $response = $this->http
                ->withHeaders(['Add-Padding' => 'true'])
                ->timeout($guard->breachCheckTimeout())
                ->get(self::ENDPOINT.$prefix)
                ->throw();
        } catch (Throwable $e) {
            report($e);
            event(new BreachedPasswordCheckFailed($guard->name()));

            if ($guard->breachCheckFailsClosed()) {
                throw new BreachCheckUnavailable($e);
            }

            return false;
        }

        foreach (preg_split('/\r?\n/', $response->body()) ?: [] as $line) {
            $parts = explode(':', trim($line), 2);

            if (count($parts) === 2 && strtoupper($parts[0]) === $suffix) {
                return (int) $parts[1] > $guard->breachThreshold();
            }
        }

        return false;
    }
}
