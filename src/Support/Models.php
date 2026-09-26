<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Models\LoginChallenge;
use RoundlyConsulting\Auth\Models\OneTimeToken;
use RoundlyConsulting\PackageToolkit\Support\ModelResolver;

/**
 * The single seam through which the package resolves its swappable models. Every read
 * and write goes through here, so a host subclass configured under
 * `authentication.models.*` is the class the package creates and queries.
 *
 * A configured class that is a model but not a subclass of the packaged one falls back
 * to the packaged model (everything is typed against it); a non-model throws.
 */
final class Models
{
    /** @return class-string<LoginChallenge> */
    public static function challenge(): string
    {
        $class = ModelResolver::for('authentication.models.challenge', LoginChallenge::class);

        return is_a($class, LoginChallenge::class, true) ? $class : LoginChallenge::class;
    }

    /** @return class-string<OneTimeToken> */
    public static function oneTimeToken(): string
    {
        $class = ModelResolver::for('authentication.models.one_time_token', OneTimeToken::class);

        return is_a($class, OneTimeToken::class, true) ? $class : OneTimeToken::class;
    }

    /** @return class-string<Invitation> */
    public static function invitation(): string
    {
        $class = ModelResolver::for('authentication.models.invitation', Invitation::class);

        return is_a($class, Invitation::class, true) ? $class : Invitation::class;
    }

    /** @return class-string<LoginActivity> */
    public static function loginActivity(): string
    {
        $class = ModelResolver::for('authentication.models.login_activity', LoginActivity::class);

        return is_a($class, LoginActivity::class, true) ? $class : LoginActivity::class;
    }

    /** @return Builder<LoginChallenge> */
    public static function challenges(): Builder
    {
        return self::challenge()::query();
    }

    /** @return Builder<OneTimeToken> */
    public static function oneTimeTokens(): Builder
    {
        return self::oneTimeToken()::query();
    }

    /** @return Builder<Invitation> */
    public static function invitations(): Builder
    {
        return self::invitation()::query();
    }

    /** @return Builder<LoginActivity> */
    public static function loginActivities(): Builder
    {
        return self::loginActivity()::query();
    }
}
