<?php

declare(strict_types=1);

namespace SimpleAuth\Enums;

use SimpleAuth\Traits\TryFromName;

Enum Permissions : int 
{
    case DEFAULT               = 0;
    case CREATE_CHARACTER      = 2;
    case EDIT_OWN_CHARACTERS   = 4;
    case DELETE_OWN_CHARACTERS = 8;
    case RESET_OTHER_PASSWORD  = 16;
    case BAN_USER              = 32;
    case UNBAN_USER            = 64;
    case CREATE_RAID           = 128;
    case EDIT_RAID             = 256;
    case DELETE_RAID           = 512;
    case CREATE_TICK           = 1024;
    case FINALIZE_RAID         = 2048;
    case EDIT_CHARACTER_DKP    = 4096;
    case APPROVE_REQUESTS      = 8192;

    use TryFromName;

    public static function decodeMask(int $mask) : array{
        $permissions = [];
        foreach (self::cases() as $case) {
            if ($case->value & $mask){
                $permissions[] = $case;
            }
        }
        return $permissions;
    }
}