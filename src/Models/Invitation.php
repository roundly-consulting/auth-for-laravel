<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Models;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Auth\Database\Factories\InvitationFactory;
use RoundlyConsulting\Auth\Enums\InvitationStatus;
use RoundlyConsulting\Auth\Support\Retention;
use RoundlyConsulting\Auth\Support\Tables;

/**
 * An invitation to create an account on a guard. The token rotates on every send; only
 * its HMAC is stored. `payload` is the host's role/meta JSON, handed to listeners of
 * `InvitationAccepted`.
 *
 * Not final: `authentication.models.invitation` may point at a subclass.
 *
 * @property int $id
 * @property string $guard
 * @property string $email
 * @property string|null $token_hash
 * @property string|null $inviter_type
 * @property int|string|null $inviter_id
 * @property string|null $account_type
 * @property int|string|null $account_id
 * @property array<string, mixed>|null $payload
 * @property string|null $locale
 * @property int $send_count
 * @property CarbonImmutable|null $last_sent_at
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $accepted_at
 * @property CarbonImmutable|null $revoked_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 * @property CarbonInterface|null $deleted_at
 * @property-read Model|null $inviter
 * @property-read Model|null $account
 */
class Invitation extends Model
{
    /** @use HasFactory<InvitationFactory> */
    use HasFactory;

    use Prunable;
    use SoftDeletes;

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['token_hash'];

    /** @var array<string, mixed> */
    protected $attributes = ['send_count' => 0];

    public function getTable(): string
    {
        return Tables::invitations();
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function inviter(): MorphTo
    {
        return $this->morphTo('inviter');
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function account(): MorphTo
    {
        return $this->morphTo('account');
    }

    public function status(?CarbonImmutable $now = null): InvitationStatus
    {
        return match (true) {
            $this->accepted_at !== null => InvitationStatus::Accepted,
            $this->revoked_at !== null => InvitationStatus::Revoked,
            $this->expires_at->lessThanOrEqualTo($now ?? CarbonImmutable::now()) => InvitationStatus::Expired,
            default => InvitationStatus::Pending,
        };
    }

    public function isPending(?CarbonImmutable $now = null): bool
    {
        return $this->status($now) === InvitationStatus::Pending;
    }

    public function payloadValue(string $key): mixed
    {
        return $this->payload[$key] ?? null;
    }

    /**
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopePending(Builder $query, ?CarbonImmutable $now = null): Builder
    {
        return $query->whereNull('accepted_at')
            ->whereNull('revoked_at')
            ->where('expires_at', '>', $now ?? CarbonImmutable::now());
    }

    /**
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeWithStatus(Builder $query, InvitationStatus $status, ?CarbonImmutable $now = null): Builder
    {
        $now ??= CarbonImmutable::now();

        return match ($status) {
            InvitationStatus::Pending => $this->scopePending($query, $now),
            InvitationStatus::Accepted => $query->whereNotNull('accepted_at'),
            InvitationStatus::Revoked => $query->whereNull('accepted_at')->whereNotNull('revoked_at'),
            InvitationStatus::Expired => $query->whereNull('accepted_at')->whereNull('revoked_at')->where('expires_at', '<=', $now),
        };
    }

    /**
     * Finished invitations (accepted, revoked or expired) older than their guard's
     * retention.
     *
     * @return Builder<static>
     */
    public function prunable(?int $days = null): Builder
    {
        return Retention::constrain($this->newQuery(), $days, static function (Builder $query, CarbonImmutable $cutoff): void {
            $query->where(static function (Builder $finished) use ($cutoff): void {
                $finished->where('accepted_at', '<', $cutoff)
                    ->orWhere('revoked_at', '<', $cutoff)
                    ->orWhere('expires_at', '<', $cutoff);
            });
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'payload' => 'array',
            'send_count' => 'integer',
            'last_sent_at' => 'immutable_datetime',
            'expires_at' => 'immutable_datetime',
            'accepted_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
        ];
    }

    protected static function newFactory(): InvitationFactory
    {
        return InvitationFactory::new();
    }
}
