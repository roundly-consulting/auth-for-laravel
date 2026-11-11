<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Controllers\Login;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Auth\Actions\Login\RequestMagicLink;
use RoundlyConsulting\Auth\Http\Requests\EmailRequest;

final class RequestMagicLinkController
{
    public function __invoke(EmailRequest $request, RequestMagicLink $magicLink): JsonResponse
    {
        $data = $request->toData();
        $magicLink->execute($request->guardConfig()->name(), $data->email, $data->context);

        return new JsonResponse(['status' => 'sent'], 202);
    }
}
