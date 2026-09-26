<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Models;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Auth\Database\Factories\LoginActivityFactory;
use RoundlyConsulting\Auth\Enums\ActivityOutcome;
use RoundlyConsulting\Auth\Enums\ActivityType;
use RoundlyConsulting\Auth\Support\Retention;
use RoundlyConsulting\Auth\Support\Tables;

/**
 * One authentication attempt: what was tried, how it ended, from where. The package
 * records raw IP/user agent only; hosts enrich rows (country, city) from the
 * `LoginActivityRecorded` event via {@see self::enrich()}.
 *
 * Not final: `authentication.models.login_activity` may point at a subclass.
 *
 * @property int $id
 * @property string $guard
 * @property string|null $account_type
 * @property int|string|null $account_id
 * @property ActivityType $type
 * @property ActivityOutcome $outcome
 * @property string|null $method
 * @property string|null $reason
 * @property string|null $identifier
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string|null $device_fingerprint
 * @property string|null $session_id
 * @property int|null $challenge_id
 * @property bool $is_new_device
 * @property string|null $country_code
 * @property string|null $city
 * @property array<string, mixed>|null $meta
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 * @property CarbonInterface|null $deleted_at
 * @property-read Model|null $account
 */
class LoginActivity extends Model
{
    /** @use HasFactory<LoginActivityFactory> */
    use HasFactory;

    use MassPrunable;
    use SoftDeletes;

    protected $guarded = [];

    /** @var array<string, mixed> */
    protected $attributes = ['is_new_device' => false];

    public function getTable(): string
    {
        return Tables::loginActivities();
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function account(): MorphTo
    {
        return $this->morphTo('account');
    }

    /**
     * Attach host-resolved location data (e.g. from a geolocation listener).
     */
    public function enrich(?string $countryCode, ?string $city): void
    {
        $this->newQuery()->whereKey($this->getKey())->update([
            'country_code' => $countryCode === null ? null : strtoupper(substr($countryCode, 0, 2)),
            'city' => $city === null ? null : mb_substr($city, 0, 255),
        ]);

        $this->refresh();
    }

    /**
     * Rows older than their guard's `activity.retention_days`.
     *
     * @return Builder<static>
     */
    public function prunable(?int $days = null): Builder
    {
        return Retention::constrain($this->newQuery(), $days, static function (Builder $query, CarbonImmutable $cutoff): void {
            $query->where('created_at', '<', $cutoff);
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => ActivityType::class,
            'outcome' => ActivityOutcome::class,
            'is_new_device' => 'boolean',
            'challenge_id' => 'integer',
            'meta' => 'array',
        ];
    }

    protected static function newFactory(): LoginActivityFactory
    {
        return LoginActivityFactory::new();
    }
}
