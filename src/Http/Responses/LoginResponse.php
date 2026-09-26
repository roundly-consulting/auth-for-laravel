<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use RoundlyConsulting\Auth\DataTransferObjects\LoginResult;
use RoundlyConsulting\Auth\DataTransferObjects\TokenPair;
use RoundlyConsulting\Auth\Http\Resources\ChallengeResource;
use RoundlyConsulting\Auth\Http\Resources\TokenPairResource;

/**
 * Renders a {@see LoginResult} as the token pair or the challenge — both 200.
 */
final class LoginResponse
{
    public static function make(LoginResult $result, Request $request): JsonResponse
    {
        if ($result->tokens !== null) {
            return self::tokens($result->tokens, $request);
        }

        return (new ChallengeResource($result->challenge))->toResponse($request)->setStatusCode(200);
    }

    public static function tokens(TokenPair $tokens, Request $request): JsonResponse
    {
        return (new TokenPairResource($tokens))->toResponse($request)->setStatusCode(200);
    }

    /**
     * A 202 acknowledgement that deliberately says nothing about the account.
     */
    public static function status(string $status, int $code = 202): JsonResponse
    {
        return new JsonResponse(['status' => $status], $code);
    }

    /**
     * A credential-change response carrying the re-issued pair (or null): when non-null
     * the client MUST swap to it — its previous access token died with the `tv` bump.
     *
     * @param  array<string, mixed>  $body
     */
    public static function withTokens(array $body, ?TokenPair $tokens, Request $request, int $code = 200): JsonResponse
    {
        $body['tokens'] = $tokens === null ? null : (new TokenPairResource($tokens))->toArray($request);

        return new JsonResponse($body, $code);
    }
}
