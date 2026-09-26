<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

/**
 * The login requires enrolling a new factor, but this guard does not allow enrolment in the challenge (or the email is unverified).
 */
final class EnrolmentRequired extends AuthException
{
    public function errorCode(): string
    {
        return 'enrolment_required';
    }

    public function status(): int
    {
        return 403;
    }
}
