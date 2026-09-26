<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Models;

use Illuminate\Auth\Authenticatable as AuthenticatableConcern;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Notifications\Notifiable;
use RoundlyConsulting\Auth\Concerns\HasAuthentication;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Tests\Fixtures\Factories\UserFactory;
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\RefreshTokens\Traits\HasRefreshTokens;
use RoundlyConsulting\TwoFactor\Concerns\HasTwoFactorAuthentication;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

final class User extends Model implements Account, HasPasskeys, TwoFactorAuthenticatable
{
    use AuthenticatableConcern;
    use HasAuthentication;

    /** @use HasFactory<UserFactory> */
    use HasFactory;

    use HasRefreshTokens;
    use HasTwoFactorAuthentication;
    use InteractsWithPasskeys;
    use Notifiable;
    use SoftDeletes;

    protected $table = 'users';

    protected $guarded = [];

    protected $hidden = ['password'];

    protected function casts(): array
    {
        return [...$this->authenticationCasts(), ...$this->twoFactorCasts(), 'email_verified_at' => 'datetime'];
    }

    protected static function newFactory(): UserFactory
    {
        return UserFactory::new();
    }
}
