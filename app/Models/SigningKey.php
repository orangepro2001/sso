<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SigningKey extends Model
{
    protected $fillable = ['kid', 'alg', 'private_key', 'public_key', 'active', 'retired_at'];

    protected $hidden = ['private_key'];

    protected $casts = [
        'private_key' => 'encrypted',
        'active' => 'boolean',
        'retired_at' => 'datetime',
    ];
}
