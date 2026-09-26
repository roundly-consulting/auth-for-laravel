<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Http\Requests;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\DataTransferObjects\InvitationData;
use RoundlyConsulting\Auth\Rules\SupportedLocale;

final class CreateInvitationRequest extends AuthenticationRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'email' => ['required', 'string', 'email', 'max:255'],
            'payload' => ['nullable', 'array'],
            'locale' => ['nullable', 'string', new SupportedLocale($this->guardConfig())],
            'ttl' => ['nullable', 'integer', 'min:60', 'max:31536000'],
            'send' => ['nullable', 'boolean'],
        ];
    }

    public function toData(): InvitationData
    {
        $inviter = $this->user($this->guardConfig()->laravelGuard());
        $ttl = $this->validated('ttl');

        return new InvitationData(
            email: $this->validatedString('email'),
            payload: $this->validatedArray('payload'),
            invitedBy: $inviter instanceof Model ? $inviter : null,
            locale: $this->validatedNullableString('locale'),
            ttl: is_numeric($ttl) ? (int) $ttl : null,
            send: $this->boolean('send', true),
        );
    }
}
