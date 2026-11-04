<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;

/**
 * No demo data by design: accounts come from the bootstrap administrator, and
 * clients from the console. Seeding credentials would be a footgun in production.
 */
class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        //
    }
}
