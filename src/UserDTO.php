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
    public ?string $user_password;
    public null|string|BackedEnum $user_status;
    public null|string|BackedEnum $user_role;
    public null|int $user_permissions;
    public null|int $user_dkp;
    public null|string|DateTime $user_created;
    public ?string $user_ip_address;
    public ?string $user_selector;
    public ?string $user_validator;

    public function __construct()
    {
        //throw new \Exception('Not implemented');
    }

    public function enumerate(string $statusEnum, string $roleEnum){
        if(is_string($this->user_status))
            $this->user_status = $statusEnum::tryFromName($this->user_status) ?? $statusEnum::from(0);
        if(is_string($this->user_role))
            $this->user_role = $roleEnum::tryFromName($this->user_role) ?? $roleEnum::from(0);
        if(is_string($this->user_created))
            $this->user_created = DateTime::createFromFormat('Y-m-d',$this->user_created);
    }
}
