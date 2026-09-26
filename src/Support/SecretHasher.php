<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Hash\Hmac;
use SensitiveParameter;

/**
 * Keyed HMAC-SHA-256 (hex) for everything the package stores or keys by a secret:
 * emailed links and codes, challenge tokens, device fingerprints, throttle keys.
 *
 * A plain hash of a 6-digit code is reversed by enumerating 10⁶ values; with the key a
 * database dump alone is useless. Binding the guard and purpose (and the email, for
 * codes) into the MAC input means a secret can never be replayed under another guard
 * or purpose.
 *
 * The key is `authentication.hash_key`, or — when unset — derived from the decoded
 * APP_KEY (never the raw app key). Rotating either invalidates every outstanding
 * secret; `APP_PREVIOUS_KEYS` is deliberately not consulted.
 */
final class SecretHasher
{
    private ?string $key = null;

    /**
     * Link secrets: computable from what a consume endpoint receives (the token alone).
     */
    public function link(string $guard, string $purpose, #[SensitiveParameter] string $token): string
    {
        return $this->mac("link|{$guard}|{$purpose}|{$token}");
    }

    /**
     * Code secrets: bound to one address, so a 6-digit code is only ever guessable
     * against the account it was sent to.
     */
    public function code(string $guard, string $purpose, string $email, #[SensitiveParameter] string $code): string
    {
        return $this->mac("code|{$guard}|{$purpose}|{$email}|{$code}");
    }

    /**
     * A device / request fingerprint over the given parts (nulls are kept positional).
     */
    public function fingerprint(string $guard, ?string ...$parts): string
    {
        return $this->mac('fp|'.$guard.'|'.implode('|', array_map(static fn (?string $part): string => $part ?? '', $parts)));
    }

    /**
     * An identifier (email, username) as it may appear in cache keys or activity rows.
     */
    public function identifier(string $guard, #[SensitiveParameter] string $identifier): string
    {
        return $this->mac("id|{$guard}|{$identifier}");
    }

    public function usesDerivedKey(): bool
    {
        return ! is_string(config('authentication.hash_key')) || trim((string) config('authentication.hash_key')) === '';
    }

    private function mac(#[SensitiveParameter] string $message): string
    {
        return (new Hmac(HashAlgorithm::Sha256))->signHex($message, $this->key());
    }

    private function key(): string
    {
        if ($this->key !== null) {
            return $this->key;
        }

        $configured = config('authentication.hash_key');

        if (is_string($configured) && trim($configured) !== '') {
            return $this->key = $configured;
        }

        return $this->key = (new Hmac(HashAlgorithm::Sha256))->sign('authentication-secrets', $this->appKey());
    }

    private function appKey(): string
    {
        $key = config('app.key');

        if (! is_string($key) || $key === '') {
            throw AuthenticationMisconfigured::because('Neither authentication.hash_key nor app.key is set; one-time secrets cannot be keyed.');
        }

        if (! str_starts_with($key, 'base64:')) {
            return $key;
        }

        try {
            return Base64::decode(substr($key, 7));
        } catch (InvalidEncodingException $e) {
            throw AuthenticationMisconfigured::because('app.key carries a base64: prefix but is not valid base64.');
        }
    }
}
