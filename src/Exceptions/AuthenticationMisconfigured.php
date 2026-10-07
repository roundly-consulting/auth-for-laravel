<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The host configuration cannot work. The detailed reason (naming the exact config key)
 * is the exception message, for logs and `authentication:check`; clients only ever see
 * it when `app.debug` is on.
 */
class AuthenticationMisconfigured extends AuthException
{
    public static function because(string $reason): static
    {
        $exception = new static;
        $exception->message = $reason;

        return $exception;
    }

    public static function routesAlreadyRegistered(string $guard): static
    {
        return static::because("Routes for the authentication guard [{$guard}] are already registered (routes.enabled and a manual Authentication::routes() call?).");
    }

    public static function routesShared(string $guard, string $what, string $value, string $owner): static
    {
        return static::because("Routes for the authentication guard [{$guard}] use the {$what} [{$value}], already taken by guard [{$owner}]; give each guard its own routes.{$what} (or ->{$what}()).");
    }

    public function errorCode(): string
    {
        return 'misconfigured';
    }

    public function status(): int
    {
        return 500;
    }

    public function render(Request $request): JsonResponse
    {
        $message = config('app.debug') === true ? $this->getMessage() : $this->translatedMessage();

        return new JsonResponse(['message' => $message, 'code' => $this->errorCode()], $this->status(), $this->headers());
    }

    /**
     * Misconfiguration is an operator error: let the host's handler report it.
     */
    public function report(): bool
    {
        return false;
    }
}
