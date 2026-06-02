<?php

declare(strict_types=1);

namespace SimpleAuth;

use BackedEnum;
use PDO;
use SimpleAuth\Throwable\SimpleAuthException;
use SimpleAuth\Enums\ErrorCode;
use SimpleAuth\Enums\Permissions;
use SimpleAuth\Enums\Status;
use SimpleAuth\Enums\Role;
use SimpleAuth\Traits\TryFromName;
use SimpleAuth\UserDTO;

class Administration
{
    public function __construct(private PDO $Connection, private $Status = Status::class, private $Role = Role::class, private $Permissions = Permissions::class, public ?UserDTO $User){
        try{
            if(is_null($this->Connection->getAttribute(PDO::ATTR_CONNECTION_STATUS)))
                throw new SimpleAuthException("Database Error",ErrorCode::DATABASE_ERROR->value);
        }
        catch (\Exception $e) {
            throw new SimpleAuthException("Database Error",ErrorCode::DATABASE_ERROR->value, $e);
        }
        if(is_null($this->Status::tryFrom(0)) || $this->Status::tryFrom(0)->name !== "UNKNOWN")
            throw new SimpleAuthException("Status Enum must have UNKNOWN with a value of 0",ErrorCode::INVALID_STATUS_ENUM->value);
        if(is_null($this->Role::tryFrom(0)) || $this->Role::tryFrom(0)->name !== "UNKNOWN")
            throw new SimpleAuthException("Roles Enum must have UNKNOWN with a value of 0",ErrorCode::INVALID_ROLE_ENUM->value);
    }

    public function newUser(){
        unset($this->User);
        $this->User = new UserDTO;
        return $this;
    }

    public function setUsername(string $username){
        $this->User->user_name = $username;
        return $this;
    }

    public function setEmail(string $email){
        $this->User->user_email = $email;
    }

    public function setPassword(string $unhasedPassword){
        $this->User->user_password = password_hash($unhasedPassword,PASSWORD_DEFAULT);
        return $this;
    }

    public function setStatus(BackedEnum $status) {
        if ($status instanceof($this->Status)){
            $this->User->user_status = $status;
            return $this;
        }
        throw new SimpleAuthException("Invalid User Status", ErrorCode::INVALID_STATUS_ENUM->value);
    }

    public function setRole(BackedEnum $role) {
        if ($role instanceof($this->Role)){
            $this->User->user_role = $role;
            return $this;
        }
        throw new SimpleAuthException("Invalid User Role", ErrorCode::INVALID_ROLE_ENUM->value);
    }

    public function resetPermissions(BackedEnum $defaultPermissions = Permissions::DEFAULT){
        unset($this->User->user_permissions);
        if($defaultPermissions instanceof $this->Permissions){
            $this->User->user_permissions = $defaultPermissions->value;
            return $this;
        }
        throw new SimpleAuthException("Invalid Default Permission", ErrorCode::INVALID_PERMISSION_ENUM->value);
    }

    public function addPermission(BackedEnum $addPermission){
        if($addPermission instanceof $this->Permissions){
            $this->User->user_permissions = $this->User->user_permissions | $addPermission->value;        
            return $this;
        }
        throw new SimpleAuthException("Invalid Add Permission", ErrorCode::INVALID_PERMISSION_ENUM->value);
    }

    public function removePermission() {

    }




}
