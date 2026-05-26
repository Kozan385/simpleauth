<?php
declare(strict_types=1);

namespace SimpleAuth\Traits;

trait TryFromName
{

public static function tryFromName(string $name): ?self 
    {
        foreach (self::cases() as $case) {
            if ($case->name === $name) {
                return $case;
            }
        }
        return null;
    }
}
