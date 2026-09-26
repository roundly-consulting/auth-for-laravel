<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Actions\Activity;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Guards\GuardRegistry;
use RoundlyConsulting\Auth\Models\LoginActivity;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\Auth\Support\Models;

/**
 * The account's own login activity on a guard, newest first.
 */
final readonly class ListLoginActivity
{
    public function __construct(private GuardRegistry $guards) {}

    /**
     * @return LengthAwarePaginator<int, LoginActivity>
     */
    public function execute(string $guard, Account $account, int $perPage = 20): LengthAwarePaginator
    {
        $this->guards->get($guard);
        $model = AccountModels::of($account);

        return Models::loginActivities()
            ->where('guard', $guard)
            ->where('account_type', $model->getMorphClass())
            ->where('account_id', $model->getKey())
            ->latest()
            ->latest('id')
            ->paginate(max(1, min(100, $perPage)));
    }
}
