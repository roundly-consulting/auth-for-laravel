<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Auth\AuthenticationManager;
use RoundlyConsulting\Auth\Guards\AccountRepository;
use RoundlyConsulting\Auth\Guards\GuardRegistry;

/**
 * Incident response: ends every session of one account.
 */
final class LogoutEverywhereCommand extends Command
{
    protected $signature = 'authentication:logout-everywhere {guard : The authentication guard} {id : The account key}';

    protected $description = 'Revoke every session and access token of an account';

    public function handle(GuardRegistry $guards, AuthenticationManager $authentication): int
    {
        $guard = $guards->get($this->text('guard'));
        $id = $this->text('id');

        // A key not shaped like authentication.key_type finds nothing.
        $account = (new AccountRepository($guard))->findByKey($id);

        if ($account === null) {
            $this->components->error("No [{$guard->name()}] account with key [{$id}].");

            return self::FAILURE;
        }

        $revoked = $authentication->guard($guard->name())->logoutEverywhere($account);

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
