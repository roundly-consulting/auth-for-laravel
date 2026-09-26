<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Support;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Auth\Guards\GuardRegistry;

/**
 * Builds a per-guard retention constraint: each guard's rows are pruned after that
 * guard's own `activity.retention_days`, unless an explicit number of days is given.
 */
final class Retention
{
    public const int DEFAULT_DAYS = 90;

    /**
     * @template TModel of Model
     *
     * @param  Builder<TModel>  $query
     * @param  Closure(Builder<TModel>, CarbonImmutable): void  $older
     * @return Builder<TModel>
     */
    public static function constrain(Builder $query, ?int $days, Closure $older): Builder
    {
        $now = CarbonImmutable::now();

        if ($days !== null) {
            $older($query, $now->subDays(max(0, $days)));

            return $query;
        }

        $retention = self::retentionByGuard();

        return $query->where(static function (Builder $scoped) use ($retention, $now, $older): void {
            foreach ($retention as $guard => $guardDays) {
                $scoped->orWhere(static function (Builder $guardQuery) use ($guard, $guardDays, $now, $older): void {
                    $guardQuery->where('guard', $guard);
                    $older($guardQuery, $now->subDays($guardDays));
                });
            }

            // Rows of a guard that has since been removed from config keep the default.
            $scoped->orWhere(static function (Builder $orphaned) use ($retention, $now, $older): void {
                $orphaned->whereNotIn('guard', array_keys($retention));
                $older($orphaned, $now->subDays(self::DEFAULT_DAYS));
            });
        });
    }

    /**
     * @return array<string, int>
     */
    private static function retentionByGuard(): array
    {
        $registry = app(GuardRegistry::class);
        $retention = [];

        foreach ($registry->all() as $name => $guard) {
            $retention[$name] = $guard->activityRetentionDays();
        }

        return $retention;
    }
}
