<?php
declare(strict_types=1);

namespace SimpleAuth;

use BackedEnum;
use PDO;
use Exception;
use SimpleAuth\Enums\ErrorCode;
use SimpleAuth\Enums\Status;
use SimpleAuth\Enums\Role;
use SimpleAuth\Enums\Permissions;
use SimpleAuth\Throwable\SimpleAuthException;

Class Authenticate {

    private array $User;
    private bool $authenticated;

    public function __construct(private PDO $Connection, private $Status = Status::class, private $Role = Role::class){
        try{
            if(is_null($this->Connection->getAttribute(PDO::ATTR_CONNECTION_STATUS)))
                throw new SimpleAuthException("Database Error",ErrorCode::DATABASE_ERROR->value);
        }
        catch (\Exception $e) {
            throw new SimpleAuthException("Database Error",ErrorCode::DATABASE_ERROR->value, $e);
        }
        if(!$this->Status::tryFrom(0)->name === "UNKNOWN")
            throw new SimpleAuthException("Status Enum must have UNKNOWN with a value of 0",ErrorCode::INVALID_STATUS_ENUM->value);
        if(!$this->Role::tryFrom(0)->name === "UNKNOWN")
            throw new SimpleAuthException("Roles Enum must have UNKNOWN with a value of 0",ErrorCode::INVALID_ROLE_ENUM->value);
        echo "<h1>Welcome To Simple Auth!</h1><br>";

    }

    public function lookupUsername(string $username){
        unset($this->User);
        $stmt = $this->Connection->prepare("SELECT * FROM users WHERE user_name =?;");
        $stmt->execute([$username]);
        $this->User = match($stmt->rowCount()){
            0 => throw new SimpleAuthException("User Not Found", ErrorCode::USERNAME_NOT_FOUND->value),
            1 => $stmt->fetch(PDO::FETCH_ASSOC),
            default => throw new SimpleAuthException("Username not unique", ErrorCode::USERNAME_NOT_UNIQUE),
        };
        
        $this->User['user_status'] = STATUS::tryFromName($this->User['user_status']) ?? $this->Status::UNKNOWN;
        $this->User['user_role'] = ROLE::tryFromName($this->User['user_role']) ?? $this->Status::UNKNOWN;
        return $this;
    }

    public function changePassword(string $newPassword): Authenticate{
        if(is_null($this->User))
            throw new Exception("No user selected");
        $newPassword = password_hash($newPassword,PASSWORD_DEFAULT);
        $stmt = $this->Connection->prepare("UPDATE users SET user_password = ? WHERE user_id = ?;");
        $stmt->execute([$newPassword, $this->User['user_id']]);
        $result = $stmt->rowCount();
        $this->User['user_password'] = $newPassword;
        return $this;
    }

    public function authenticateWithPassword(string $password): Authenticate{
        if ($this->User['user_status']->value > 0) {
            if(password_verify($password,$this->User['user_password'])){
                $this->authenticated = true;
                return $this;
            } else {
            throw new Exception("Authentication Failed");
            }
        } else {
            throw new Exception($this->User['user_id'] . " tried to authenticate but is " . $this->User['user_id']->name . ".");
        }
    }

    public function isAuthenticated(): bool{
        return $this->authenticated ?? false;
    }

    public function getUser(){
        return $this->User;
    }
}
