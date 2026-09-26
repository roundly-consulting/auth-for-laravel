<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Activity;

use RoundlyConsulting\Auth\DataTransferObjects\PruneReport;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Deletes what is no longer needed: challenges and one-time tokens a day past expiry,
 * finished invitations and activity rows past their guard's retention (or `$days`).
 * Force-deletes — soft-deleted rows are pruned too. The models are also `Prunable` for
 * `model:prune`.
 */
final class PruneAuthenticationData
{
    public function execute(?int $days = null): PruneReport
    {
        return new PruneReport(
            challenges: (int) (new (Models::challenge()))->prunable()->withTrashed()->forceDelete(),
            oneTimeTokens: (int) (new (Models::oneTimeToken()))->prunable()->withTrashed()->forceDelete(),
            invitations: (int) (new (Models::invitation()))->prunable($days)->withTrashed()->forceDelete(),
            activities: (int) (new (Models::loginActivity()))->prunable($days)->withTrashed()->forceDelete(),
        );
    }
}
