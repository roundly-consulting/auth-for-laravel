<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Guards;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\SoftDeletingScope;
use Normalizer;
use RoundlyConsulting\Auth\Contracts\Account;
use RoundlyConsulting\Auth\Exceptions\AuthenticationMisconfigured;
use RoundlyConsulting\Auth\Support\AccountModels;
use RoundlyConsulting\PackageToolkit\Support\RawExpression;

/**
 * The only class that queries a guard's account model. Soft-deleted accounts never
 * log in (every finder excludes them), but their emails stay taken.
 */
final readonly class AccountRepository
{
    public function __construct(private GuardConfig $guard) {}

    public function morphClass(): string
    {
        return $this->newModel()->getMorphClass();
    }

    /**
     * Refuse an account of another guard's model. The morph class is the isolation
     * boundary (refresh families, challenges, one-time tokens, activity): acting on a
     * foreign account through this guard would mint tokens whose `sub` names an account
     * of this guard with the same key.
     *
     * @throws AuthenticationMisconfigured
     */
    public function ensureOwns(Account $account): void
    {
        $morphClass = AccountModels::of($account)->getMorphClass();

        if ($morphClass !== $this->morphClass()) {
            throw AuthenticationMisconfigured::because("The account [{$morphClass}] belongs to another guard than [{$this->guard->name()}].");
        }
    }

    public function newModel(): Model&Account
    {
        $model = $this->guard->model();

        return new $model;
    }

    /**
     * `identifier.columns` tried in order; the first column with a match wins
     * (cross-column uniqueness is the host's responsibility).
     */
    public function findForLogin(string $identifier): ?Account
    {
        $identifier = $this->normalize($identifier);

        if ($identifier === '') {
            return null;
        }

        foreach ($this->guard->identifierColumns() as $column) {
            $account = $this->whereIdentifier($this->query(), $column, $identifier)->first();

            if ($account instanceof Account) {
                return $account;
            }
        }

        return null;
    }

    public function findByEmail(string $email, bool $withTrashed = false): ?Account
    {
        $email = $this->normalizeEmail($email);

        if ($email === '') {
            return null;
        }

        $query = $withTrashed ? $this->queryWithTrashed() : $this->query();
        $account = $this->whereIdentifier($query, $this->guard->emailColumn(), $email)->first();

        return $account instanceof Account ? $account : null;
    }

    public function findByKey(int|string $key): ?Account
    {
        $account = $this->query()->whereKey($key)->first();

        return $account instanceof Account ? $account : null;
    }

    /**
     * Whether an account (including a soft-deleted one) already holds the address.
     */
    public function emailTaken(string $email): bool
    {
        return $this->findByEmail($email, withTrashed: true) !== null;
    }

    public function normalizeEmail(string $email): string
    {
        return $this->normalize($email);
    }

    /**
     * Trimmed, Unicode-composed (NFC) — `josé` typed as `e` + a combining accent is the
     * same address as the precomposed `é`, one account and one throttle bucket — and
     * lowercased unless the guard keeps identifiers as typed.
     */
    public function normalize(string $identifier): string
    {
        $identifier = self::compose(trim($identifier));

        return $this->guard->lowercasesIdentifiers() ? mb_strtolower($identifier) : $identifier;
    }

    /**
     * Canonical composition (NFC); invalid UTF-8 is left as it is.
     */
    public static function compose(string $value): string
    {
        $composed = Normalizer::normalize($value, Normalizer::FORM_C);

        return is_string($composed) ? $composed : $value;
    }

    /**
     * @return Builder<Model&Account>
     */
    private function query(): Builder
    {
        return $this->newModel()->newQuery();
    }

    /**
     * @return Builder<Model&Account>
     */
    private function queryWithTrashed(): Builder
    {
        $model = $this->newModel();

        return in_array(SoftDeletes::class, class_uses_recursive($model), true)
            ? $model->newQuery()->withoutGlobalScope(SoftDeletingScope::class)
            : $model->newQuery();
    }

    /**
     * @param  Builder<Model&Account>  $query
     * @return Builder<Model&Account>
     */
    private function whereIdentifier(Builder $query, string $column, string $value): Builder
    {
        if (! $this->guard->caseInsensitiveLookup()) {
            return $query->where($column, $value);
        }

        $wrapped = $query->getQuery()->getGrammar()->wrap($column);

        return $query->where(new RawExpression("lower({$wrapped})"), '=', mb_strtolower($value));
    }
}
