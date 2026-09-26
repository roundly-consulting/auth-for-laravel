<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use RoundlyConsulting\Auth\Actions\Sessions\LogoutEverywhere;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\PackageToolkit\Enums\KeyType;

/**
 * Incident response: ends every session of one account.
 */
final class LogoutEverywhereCommand extends Command
{
    protected $signature = 'authentication:logout-everywhere {guard : The authentication guard} {id : The account key}';

    protected $description = 'Revoke every session and access token of an account';

    public function handle(GuardRegistry $guards, LogoutEverywhere $logout): int
    {
        $guard = $guards->get($this->text('guard'));
        $id = $this->text('id');

        $valid = match (KeyType::fromConfig('authentication.key_type')) {
            KeyType::BigInt => ctype_digit($id),
            KeyType::Uuid => Str::isUuid($id),
            KeyType::Ulid => Str::isUlid($id),
        };

        $account = $valid ? (new AccountRepository($guard))->findByKey($id) : null;

        if ($account === null) {
            $this->components->error("No [{$guard->name()}] account with key [{$id}].");

            return self::FAILURE;
        }

        $revoked = $logout->execute($guard->name(), $account);

        $this->components->info("Logged out everywhere: {$revoked} session(s) revoked, every access token invalidated.");

        return self::SUCCESS;
    }

    /**
     * A string argument or option ('' when absent).
     */
    private function text(string $key): string
    {
        $value = $this->hasArgument($key) ? $this->argument($key) : $this->option($key);

        return is_string($value) ? $value : '';
    }
}
