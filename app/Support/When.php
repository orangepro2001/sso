<?php

namespace App\Support;

use Carbon\CarbonInterface;

/**
 * Times as the people using the console read them.
 *
 * The application clock stays UTC: tokens, codes and reset links are compared
 * against naive timestamps, and moving the clock would shift every expiry by nine
 * hours. Only what is printed moves to the display zone.
 */
final class When
{
    public static function at(?CarbonInterface $time, string $format = 'Y-m-d H:i'): string
    {
        return $time === null ? '—' : $time->copy()->setTimezone(self::zone())->format($format);
    }

    public static function ago(?CarbonInterface $time, string $never = '없음'): string
    {
        return $time === null ? $never : $time->copy()->locale('ko')->diffForHumans();
    }

    public static function zone(): string
    {
        return (string) config('sso.display_timezone', 'Asia/Seoul');
    }
}
