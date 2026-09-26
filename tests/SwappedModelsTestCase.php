<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests;

use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomInvitation;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomLoginActivity;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomLoginChallenge;
use RoundlyConsulting\Auth\Tests\Fixtures\Models\Swapped\CustomOneTimeToken;

/**
 * Boots with every swappable model replaced by a host subclass — before the providers
 * boot, as a host would configure it.
 */
abstract class SwappedModelsTestCase extends TestCase
{
    protected function configBeforeBoot(): array
    {
        return [
            ...parent::configBeforeBoot(),
            'authentication.models.challenge' => CustomLoginChallenge::class,
            'authentication.models.one_time_token' => CustomOneTimeToken::class,
            'authentication.models.invitation' => CustomInvitation::class,
            'authentication.models.login_activity' => CustomLoginActivity::class,
        ];
    }
}
