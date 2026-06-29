<?php

declare(strict_types=1);

namespace SimpleAuth;

use BackedEnum;
use DateTime;

class UserDTO
{
    public ?int $user_id;
    public ?string $user_name;
    public ?string $user_email;
    public ?string $user_hashed_password;
    public null|string$user_created;
    public null|string|BackedEnum $user_status;
    public null|string|BackedEnum $user_role;
    public null|int $user_permissions;
    public ?string $user_cookie_selector;
    public ?string $user_cookie_validator;
    public ?string $user_password_reset_token;
    public ?string $user_password_reset_timestamp;

    public function __construct()
    {
        //throw new \Exception('Not implemented');
    }

    public function enumerate(string $statusEnum, string $roleEnum){
        if(is_string($this->user_status))
            $this->user_status = $statusEnum::tryFromName($this->user_status) ?? $statusEnum::from(0);
        if(is_string($this->user_role))
            $this->user_role = $roleEnum::tryFromName($this->user_role) ?? $roleEnum::from(0);
    }

    public function toArray(): array
    {
        $array = get_object_vars($this);
        foreach($array as $key => $value)
            if(is_object($value)) 
                $array[$key] = $value->name;
        return $array;
    }

    public function toArrayNoID(): array
    {
        $array = $this->toArray();
        unset($array['user_id']);
        return $array;
    }

}
