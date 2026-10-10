<?php

declare(strict_types=1);

namespace RoundlyConsulting\Auth\Tests\Fixtures\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use RoundlyConsulting\Auth\Tests\Fixtures\Factories\OperatorFactory;

/**
 * A back-office operator: a saved model on no guard and no authentication account — the
 * kind of actor a support tool passes as `actor:`.
 */
final class Operator extends Model
{
    /** @use HasFactory<OperatorFactory> */
    use HasFactory;

    use SoftDeletes;

    protected $table = 'operators';

    protected $guarded = [];

    protected $hidden = ['password'];

    protected static function newFactory(): OperatorFactory
    {
        return OperatorFactory::new();
    }
}
