<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Enums\UrlKind;
use RoundlyConsulting\Auth\Guards\GuardConfig;
use SensitiveParameter;

/**
 * Renders a frontend URL template from config — never from client input, so there is
 * no open redirect. `{token}`, `{email}` and `{guard}` are rawurlencoded; `{frontend}`
 * (the guard's `frontend_url`, else app.url) and `{app}` are base URLs. The default
 * templates carry the secret in the URL fragment, which never reaches a server log or a
 * `Referer` header.
 */
final class UrlTemplate
{
    public static function render(GuardConfig $guard, UrlKind $kind, #[SensitiveParameter] string $token, ?string $email = null): string
    {
        return strtr($guard->urlTemplate($kind), [
            '{frontend}' => $guard->frontendUrl(),
            '{app}' => $guard->appUrl(),
            '{guard}' => rawurlencode($guard->name()),
            '{email}' => rawurlencode($email ?? ''),
            '{token}' => rawurlencode($token),
        ]);
    }
}
