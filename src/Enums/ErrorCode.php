<?php

declare(strict_types=1);

namespace SimpleAuth\Enums;

enum ErrorCode : int
{
    case DATABASE_ERROR = 1000;
    case INVALID_STATUS_ENUM = 1001;
    case INVALID_ROLE_ENUM = 1002;
    case USER_DATA_ERROR = 2000;
    case USERNAME_NOT_FOUND = 2001;
    case USERNAME_NOT_UNIQUE = 2002;
    case EMAIL_NOT_FOUND = 2003;
    case NO_USER_SELECTED = 2004;
    case USER_STATUS_ERROR = 3000;
    case USER_ACCOUNT_LOCKED = 3001;
    case USER_ACCOUNT_BANNED = 3002;
    case PASSWORD_AUTHENTICATION_FAILED = 5000;
}
