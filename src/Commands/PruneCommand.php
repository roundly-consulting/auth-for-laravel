<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Auth\AuthenticationManager;

final class PruneCommand extends Command
{
    protected $signature = 'authentication:prune {--days= : Override the activity/invitation retention in days}';

    protected $description = 'Delete expired challenges and one-time tokens, and old invitations and login activity';

    public function handle(AuthenticationManager $authentication): int
    {
        $days = $this->option('days');

        if (is_string($days) && ! ctype_digit($days)) {
            $this->components->error('--days must be a whole number.');

            return self::FAILURE;
        }

        $report = $authentication->prune(is_string($days) ? (int) $days : null);

        $this->components->twoColumnDetail('Challenges', (string) $report->challenges);
        $this->components->twoColumnDetail('One-time tokens', (string) $report->oneTimeTokens);
        $this->components->twoColumnDetail('Invitations', (string) $report->invitations);
        $this->components->twoColumnDetail('Login activity', (string) $report->activities);
        $this->components->info("Pruned {$report->total()} rows.");

        return self::SUCCESS;
    }
}
