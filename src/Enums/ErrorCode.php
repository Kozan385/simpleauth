<?php

declare(strict_types=1);

namespace SimpleAuth\Enums;

enum ErrorCode : int
{
    //Authentication Failures
    case AUTHENTICATION_FAILED  = 1000;
    case USERNAME_NOT_FOUND     = 1001;
    case EMAIL_NOT_FOUND        = 1002;
    case USER_STATUS_ERROR      = 1003;
    //Registeration Errors
    case USER_DATA_ERROR        = 2000;
    case USERNAME_NOT_UNIQUE    = 2001;
    case EMAIL_NOT_UNIQUE       = 2002;
    case SELECTOR_NOT_UNIQUE    = 2003;
    //Process Errors
    case NO_USER_SELECTED       = 9001;
    case MISSING_REQUIRED_FIELD = 9002;
    //Configuration Errors
    case DATABASE_ERROR         = 10000;
    case INVALID_ENUM           = 10001;


    public function message():string {
        return match ($this) {
        //Authentication Failures
        self::AUTHENTICATION_FAILED  => 'Authentication Failed.',
        self::USERNAME_NOT_FOUND     => 'Username Not Found.',
        self::EMAIL_NOT_FOUND        => 'Email Not Found.',
        self::USER_STATUS_ERROR      => 'User Status Error.',
        //Registeration Errors 
        self::USER_DATA_ERROR        => 'User Data Error.',
        self::USERNAME_NOT_UNIQUE    => 'Duplicate Username.',
        self::EMAIL_NOT_UNIQUE       => 'Duplicate Email Address.',
        self::SELECTOR_NOT_UNIQUE    => 'Duplicate Cookie Selector.',
        //Process Errors
        self::NO_USER_SELECTED       => 'No User Selected.',
        self::MISSING_REQUIRED_FIELD => 'Missing Required Field.',
        //Configuration Errors
        self::DATABASE_ERROR         => 'Database Error.',
        self::INVALID_ENUM           => 'Invalid ENUM.',
        };       
    }
}
