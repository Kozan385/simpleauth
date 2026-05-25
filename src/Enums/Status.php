<?php

declare(strict_types=1);

namespace SimpleAuth\Enums;

Enum Status{
    case BANNED;
    case LOCKED;
    case GOOD;
    case UNKNOWN;
}