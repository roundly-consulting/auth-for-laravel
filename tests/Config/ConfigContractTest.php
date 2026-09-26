<?php

declare(strict_types=1);

/**
 * Both directions. Every per-guard leaf is read in GuardConfig by a literal offset chain on
 * `$this->settings` (mapped to `authentication.defaults`); `guards` is read wholesale by
 * the registry. The one shipped guard leaf is consumed through that merge — as the
 * merged `model` offset — so it is listed as allowUnread. The key type and the model swap
 * keys are read through the toolkit (`KeyType::fromConfig`, `ModelResolver::for`), not
 * `config()`, so those exact literals count as reads.
 */
it('ships exactly the config keys it reads', function (): void {
    expect(__DIR__.'/../../config/authentication.php')->toSatisfyConfigContract(__DIR__.'/../../src', [
        'sectionVariables' => ['GuardConfig.php' => ['$this->settings' => 'authentication.defaults']],
        'allowUnread' => ['authentication.guards.users.model'],
        'extraReadPrefixes' => [
            'authentication.key_type',
            'authentication.models.challenge',
            'authentication.models.one_time_token',
            'authentication.models.invitation',
            'authentication.models.login_activity',
        ],
    ]);
});
