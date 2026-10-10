<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Support;

use Closure;
use Illuminate\Http\JsonResponse;
use RuntimeException;
use Throwable;

/**
 * A host's own error shape (RFC 9457 problem details), the kind a host maps package
 * exceptions to with `$exceptions->map()`. It stays unreported like the exception it
 * replaces, and tells `$onReport` when Laravel reports it.
 */
final class ApiProblem extends RuntimeException
{
    public function __construct(
        public readonly string $type,
        string $title,
        public readonly int $status,
        ?Throwable $previous = null,
        private readonly ?Closure $onReport = null,
    ) {
        parent::__construct($title, 0, $previous);
    }

    public function render(): JsonResponse
    {
        return new JsonResponse(
            ['type' => $this->type, 'title' => $this->getMessage(), 'status' => $this->status],
            $this->status,
            ['Content-Type' => 'application/problem+json', 'Cache-Control' => 'no-store, private'],
        );
    }

    public function report(): bool
    {
        if ($this->onReport !== null) {
            ($this->onReport)($this);
        }

        return true;
    }
}
