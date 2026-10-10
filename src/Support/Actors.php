<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\DataTransferObjects\ActorData;
use RoundlyConsulting\Auth\DataTransferObjects\CurrentToken;

/**
 * @internal the `actor:` argument of the host-callable writes
 *
 * Who acted on an account, when it was someone else. The actor is informational only: no
 * guard or ownership check, so an admin of another guard or a model that is no account
 * is fine. The account itself is no actor, so a host may pass `$request->user()` without
 * checking.
 */
final class Actors
{
    /**
     * The actor when it is not the account; null for none or the account itself. Refuses,
     * before anything is written, an unsaved model — and another actor together with a
     * current token: that token is the account's own device, and an admin passing their
     * own would get it denylisted while no device of the account is kept.
     *
     * @throws InvalidArgumentException
     */
    public static function other(Account $account, ?Model $actor, ?CurrentToken $current = null): ?Model
    {
        if ($actor === null) {
            return null;
        }

        if (! $actor->exists || $actor->getKey() === null) {
            throw new InvalidArgumentException('The actor must be a saved model.');
        }

        if (AccountModels::of($account)->is($actor)) {
            return null;
        }

        if ($current !== null) {
            throw new InvalidArgumentException('Another actor cannot keep a current token: pass the account\'s own token, or none.');
        }

        return $actor;
    }

    /**
     * The actor as the reference a notification carries.
     */
    public static function reference(?Model $actor): ?ActorData
    {
        return $actor === null ? null : ActorData::fromModel($actor);
    }
}
