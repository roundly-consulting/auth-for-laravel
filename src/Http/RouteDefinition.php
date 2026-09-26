<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http;

/**
 * One package endpoint. `enabled` is resolved from the guard's config at registration:
 * a disabled feature is simply absent (404), revealing nothing beyond its absence.
 */
final readonly class RouteDefinition
{
    /**
     * @param  class-string  $controller
     * @param  list<string>  $middleware
     */
    public function __construct(
        public string $group,
        public string $method,
        public string $uri,
        public string $name,
        public string $controller,
        public bool $authenticated = false,
        public bool $enabled = true,
        public array $middleware = [],
    ) {}
}
