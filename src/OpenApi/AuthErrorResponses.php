<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\OpenApi;

use Dedoc\Scramble\Extensions\OperationExtension;
use Dedoc\Scramble\Support\Generator\Combined\AnyOf;
use Dedoc\Scramble\Support\Generator\Operation;
use Dedoc\Scramble\Support\Generator\Reference;
use Dedoc\Scramble\Support\Generator\Response;
use Dedoc\Scramble\Support\Generator\Schema;
use Dedoc\Scramble\Support\Generator\Types\ArrayType;
use Dedoc\Scramble\Support\Generator\Types\IntegerType;
use Dedoc\Scramble\Support\Generator\Types\ObjectType;
use Dedoc\Scramble\Support\Generator\Types\StringType;
use Dedoc\Scramble\Support\RouteInfo;
use ReflectionClass;
use RoundlyConsulting\Auth\Exceptions\AuthException;

/**
 * Optional extension for the dedoc/scramble OpenAPI generator. Every exception the package
 * throws renders itself as `{"message", "code", "errors"?, …extra}`, which no generator can
 * see from the routes. Registered in `config/scramble.php` (`'extensions'`), this adds that
 * body as the `AuthError` schema and a `default` response on every route the package
 * registers. Nothing else in the package depends on Scramble; without it this class is
 * never loaded.
 */
final class AuthErrorResponses extends OperationExtension
{
    public const SCHEMA = 'AuthError';

    public function handle(Operation $operation, RouteInfo $routeInfo): void
    {
        if (! self::isPackageRoute($routeInfo->route->gatherMiddleware())) {
            return;
        }

        $error = $this->schema();

        $this->widenUnprocessable($operation, $error);

        $operation->addResponse(
            Response::make('default')
                ->setDescription('An authentication error: `code` is the stable machine code, `errors` names the offending field.')
                ->setContent('application/json', $error),
        );
    }

    /**
     * A 422 from these routes is either Laravel's validation error or a package error
     * (`invalid_credentials`, `factor_failed`, …), so the documented 422 accepts both.
     */
    private function widenUnprocessable(Operation $operation, Reference $error): void
    {
        foreach ($operation->responses ?? [] as $index => $response) {
            $resolved = $response instanceof Reference ? $response->resolve() : $response;

            if (! $resolved instanceof Response || (int) $resolved->code !== 422) {
                continue;
            }

            $validation = (new ObjectType)
                ->addProperty('message', new StringType)
                ->addProperty('errors', (new ObjectType)->additionalProperties((new ArrayType)->setItems(new StringType)))
                ->setRequired(['message', 'errors']);

            $operation->responses[$index] = Response::make(422)
                ->setDescription('A validation error, or an authentication error such as `invalid_credentials` or `factor_failed`.')
                ->setContent('application/json', Schema::fromType((new AnyOf)->setItems([$validation, $error])));
        }
    }

    /**
     * @param  array<int, mixed>  $middleware
     */
    private static function isPackageRoute(array $middleware): bool
    {
        foreach ($middleware as $name) {
            if (is_string($name) && str_starts_with($name, 'authentication.guard:')) {
                return true;
            }
        }

        return false;
    }

    private function schema(): Reference
    {
        $components = $this->openApiTransformer->getComponents();

        if ($components->hasSchema(self::SCHEMA)) {
            return new Reference('schemas', self::SCHEMA, $components);
        }

        $messages = (new ArrayType)->setItems(new StringType);

        $body = (new ObjectType)
            ->addProperty('message', (new StringType)->setDescription('Translated, safe to show.'))
            ->addProperty('code', (new StringType)->enum(self::codes())->setDescription('Stable machine code; branch on this, not on the message.'))
            ->addProperty('errors', (new ObjectType)->additionalProperties($messages)->setDescription('The field the error belongs to, as in a validation error.'))
            ->addProperty('attempts_left', (new IntegerType)->setDescription('`factor_failed`: attempts left before the challenge dies.'))
            ->addProperty('retry_after', (new IntegerType)->setDescription('`too_many_attempts`: seconds until a retry may succeed (also the `Retry-After` header).'))
            ->addProperty('methods', (new ArrayType)->setItems(new StringType)->setDescription('`reauthentication_required`: the methods that can confirm.'))
            ->setRequired(['message', 'code']);

        return $components->addSchema(self::SCHEMA, Schema::fromType($body));
    }

    /**
     * Every machine code the package's exceptions carry, read from the exception classes so
     * a new one is documented without touching this list.
     *
     * @return list<string>
     */
    private static function codes(): array
    {
        $codes = [];

        foreach (glob(__DIR__.'/../Exceptions/*.php') ?: [] as $file) {
            $class = 'RoundlyConsulting\\Auth\\Exceptions\\'.basename($file, '.php');

            if (! is_subclass_of($class, AuthException::class)) {
                continue;
            }

            $reflection = new ReflectionClass($class);

            if (! $reflection->isAbstract()) {
                // errorCode() is a constant per class; skip the constructor (it translates).
                $codes[] = $reflection->newInstanceWithoutConstructor()->errorCode();
            }
        }

        $codes = array_values(array_unique($codes));
        sort($codes);

        return $codes;
    }
}
