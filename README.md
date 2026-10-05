<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/auth-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=auth-for-laravel">
    <img src="https://raw.githubusercontent.com/roundly-consulting/auth-for-laravel/main/art/hero.png" alt="Auth for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/auth-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/auth-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/auth-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/auth-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/auth-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/auth-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
  <a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/patreon-become%20a%20patron-F96854?style=flat-square&logo=patreon&logoColor=white" alt="Patreon"></a>
  <a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=auth-for-laravel#crypto"><img src="https://img.shields.io/badge/crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto"></a>
</p>
<!-- roundly-badges:end -->

# Auth for Laravel

Headless, multi-guard account authentication for Laravel: password, magic-link, email-code and
passkey login, a challenge engine for two-factor and forced enrolment, RS256 access tokens with
rotating refresh tokens and device sessions, registration, invitations, email verification,
password resets and a login-activity log — with an event for every state change and opt-in JSON
endpoints. It owns the policy and orchestration; tokens, sessions, TOTP, WebAuthn and crypto come
from the roundly security packages it builds on.

## Installation

Requires PHP 8.4 (`ext-bcmath`, `ext-mbstring`, `ext-openssl`), Laravel 12 or 13, a cache store
with atomic locks, and a mail transport.

```bash
composer require roundly-consulting/auth-for-laravel
php artisan jwt:generate-keys
php artisan authentication:install   # publishes config + migrations, prints the guard wiring
php artisan migrate
```

Wire each guard the way `authentication:install` prints it — a `jwt` guard with its own audience
and the `authentication` user provider in `config/auth.php`, plus
`RoundlyConsulting\Auth\Support\TokenVersionResolver` as `jwt.guard.token_version` (without it,
invalidation revokes nothing). `php artisan authentication:check` confirms the setup.

## Usage

Give the guard's model the contracts of the features it uses:

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use RoundlyConsulting\Auth\Concerns\HasAuthentication;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;
use RoundlyConsulting\RefreshTokens\Traits\HasRefreshTokens;
use RoundlyConsulting\TwoFactor\Concerns\HasTwoFactorAuthentication;
use RoundlyConsulting\TwoFactor\Contracts\TwoFactorAuthenticatable;

class User extends Authenticatable implements Account, HasPasskeys, TwoFactorAuthenticatable
{
    use HasAuthentication, HasRefreshTokens, HasTwoFactorAuthentication, InteractsWithPasskeys, Notifiable;

    protected function casts(): array
    {
        return [...$this->authenticationCasts(), ...$this->twoFactorCasts(), 'email_verified_at' => 'datetime'];
    }
}
```

Log in — the result is a token pair, or a challenge when a second factor is due:

```php
use RoundlyConsulting\Auth\DataTransferObjects\PasswordCredentials;
use RoundlyConsulting\Auth\Facades\Authentication;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;

$guard = Authentication::guard('users');

$result = $guard->attempt(
    new PasswordCredentials(identifier: $request->string('email')->toString(), password: $request->string('password')->toString()),
    $guard->contextFrom($request),
);

return $result->isAuthenticated()
    ? TokenPairResource::make($result->tokens)
    : ChallengeResource::make($result->challenge);   // continue with $guard->challenges()->complete(…)
```

Rotate the refresh token, or sign the account out of every device:

```php
$tokens = $guard->refresh($refreshToken, $guard->contextFrom($request));   // the old access token stops working

$guard->logoutEverywhere($user);
```

<!-- roundly-docs:start -->
## Documentation

The full documentation — configuration, every feature and its API, and testing — lives on our
website: **[roundly-consulting.com/open-source/docs/auth-for-laravel](https://roundly-consulting.com/open-source/docs/auth-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=auth-for-laravel)**

Release notes are in [CHANGELOG.md](CHANGELOG.md). To contribute, see the
[contributing guide](https://github.com/roundly-consulting/.github/blob/main/CONTRIBUTING.md).
<!-- roundly-docs:end -->

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=auth-for-laravel).
If it saves you time, please consider supporting our open-source work — a one-time donation, a
monthly pledge on Patreon or a crypto donation helps fund maintenance, new features and new
packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/Patreon-Become%20a%20patron-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Become a patron on Patreon"></a>
<a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=auth-for-laravel#crypto"><img src="https://img.shields.io/badge/Crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate crypto: BTC, ETH, BNB or SOL"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
