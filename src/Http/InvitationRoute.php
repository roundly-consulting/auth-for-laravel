<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http;

use RoundlyConsulting\Auth\Exceptions\InvitationNotFound;
use RoundlyConsulting\Auth\Models\Invitation;
use RoundlyConsulting\Auth\Support\Models;

/**
 * Resolves the `{invitation}` route parameter inside the guard — never implicit
 * route-model binding (the model is swappable and must be scoped). A non-numeric,
 * unknown or foreign id is the same 404.
 */
final class InvitationRoute
{
    public static function resolve(string $guard, string $id): Invitation
    {
        if (! ctype_digit($id)) {
            throw new InvitationNotFound;
        }

        return Models::invitations()->where('guard', $guard)->whereKey((int) $id)->first() ?? throw new InvitationNotFound;
    }
}
