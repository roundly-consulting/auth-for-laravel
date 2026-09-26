<?php

declare(strict_types=1);

return [
    'password' => [
        'too_long_bytes' => 'The password may not be longer than :max bytes.',
        'contains_identifier' => 'The password may not contain your email address.',
        'breached' => 'This password has appeared in a data leak. Please choose a different password.',
        'unavailable' => 'The password could not be checked right now. Please try again.',
        'reused' => 'The new password must be different from the current one.',
        'current_incorrect' => 'The current password is incorrect.',
    ],
    'locale' => 'The selected locale is not supported.',
    'email_taken' => 'This email address is already in use.',
    'email_unchanged' => 'This is already your email address.',
];
