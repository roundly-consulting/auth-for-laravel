<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Exceptions;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RuntimeException;
use Throwable;

/**
 * The base of every exception the package throws. Each one carries a stable machine
 * `code`, an HTTP status and a translated message, and renders itself as
 *
 *     {"message": "…", "code": "…", "errors": {"<field>": ["…"]}, …extra}
 *
 * Laravel calls {@see self::render()} on the exception itself, so no global handler is
 * touched; a host overrides the shape with `$exceptions->render(...)`.
 */
abstract class AuthException extends RuntimeException
{
    /**
     * Extra top-level members of the JSON body (`attempts_left`, `retry_after`, …).
     *
     * @var array<string, mixed>
     */
    protected array $extra = [];

    protected ?string $field = null;

    final public function __construct(?Throwable $previous = null)
    {
        parent::__construct($this->translatedMessage(), 0, $previous);
    }

    abstract public function errorCode(): string;

    abstract public function status(): int;

    /**
     * @return array<string, mixed>
     */
    public function extra(): array
    {
        return $this->extra;
    }

    public function field(): ?string
    {
        return $this->field;
    }

    public function render(Request $request): JsonResponse
    {
        $body = ['message' => $this->getMessage(), 'code' => $this->errorCode()];

        if ($this->field !== null) {
            $body['errors'] = [$this->field => [$this->getMessage()]];
        }

        return new JsonResponse([...$body, ...$this->extra], $this->status(), $this->headers());
    }

    /**
     * Expected client-facing outcomes are not reported to the host's error tracker.
     */
    public function report(): bool
    {
        return true;
    }

    /**
     * @return array<string, string>
     */
    protected function headers(): array
    {
        return ['Cache-Control' => 'no-store, private', 'Pragma' => 'no-cache'];
    }

    protected function translatedMessage(): string
    {
        $key = 'authentication::messages.errors.'.$this->errorCode();
        $message = __($key);

        return is_string($message) && $message !== $key ? $message : $this->errorCode();
    }
}
