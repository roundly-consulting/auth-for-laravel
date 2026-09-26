<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Enabled
    |--------------------------------------------------------------------------
    |
    | Placeholder setting so the service provider has something real to merge,
    | publish, and report via `php artisan about`. Replace with the package's
    | real configuration — every key here must be read somewhere under src/,
    | and ConfigContractTest enforces both directions.
    |
    */

    'enabled' => env('PACKAGE_TEMPLATE_ENABLED', true),

];
