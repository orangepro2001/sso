<?php

namespace App\Services;

use DomainException;

/**
 * A change the account rules forbid (UserAccounts): locking out the last super
 * administrator, or an administrator disabling themselves. The message is shown to
 * the person as is, so it is written in the console's language.
 */
class AccountRuleException extends DomainException
{
    public function __construct(public readonly string $field, string $message)
    {
        parent::__construct($message);
    }
}
