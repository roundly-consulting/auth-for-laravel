<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Models;

use Illuminate\Auth\Authenticatable as AuthenticatableConcern;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Concerns\HasAuthentication;
use RoundlyConsulting\Auth\Contracts\Account;

/**
 * An account with neither two-factor nor passkey support, and no Notifiable trait.
 */
final class PlainAccount extends Model implements Account
{
    use AuthenticatableConcern;
    use HasAuthentication;

    protected $table = 'clients';

    protected $guarded = [];

    protected function casts(): array
    {
        return [...$this->authenticationCasts(), 'email_verified_at' => 'datetime'];
    }
}
