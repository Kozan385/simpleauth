<?php

declare(strict_types=1);

namespace SimpleAuth\Enums;

Enum Role : int {
    case GUEST       = 1;
    case REGISTERED  = 2;
    case MEMBER      = 4;
    case VETERAN     = 8;
    case RAID_LEADER = 16;
    case OFFICER     = 32;
    case DKP_ADMIN   = 64;
    case SITE_ADMIN  = 128;
    case SUPER_ADMIN = 256;
    case UNKNOWN     = 0;
}