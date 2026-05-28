<?php

declare(strict_types=1);

namespace SimpleAuth\Enums;

use SimpleAuth\Traits\TryFromName;

Enum Status : int{
    case BANNED  = -2;
    case LOCKED  = -1;
    case UNKNOWN = 0;
    case GOOD    = 1;
    case PRIVLIEGED = 255;    

    use TryFromName;
}