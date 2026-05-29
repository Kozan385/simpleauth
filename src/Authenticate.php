<?php
declare(strict_types=1);

namespace SimpleAuth;

use PDO;
use Exception;
use SimpleAuth\Enums\ErrorCode;
use SimpleAuth\Enums\Status;
use SimpleAuth\Enums\Role;
use SimpleAuth\Throwable\SimpleAuthException;
use SimpleAuth\Traits\lookupUserName;

Class Authenticate {

    private $User;
    private bool $authenticated;

    public function __construct(private PDO $Connection, private $Status = Status::class, private $Role = Role::class){
        try{
            if(is_null($this->Connection->getAttribute(PDO::ATTR_CONNECTION_STATUS)))
                throw new SimpleAuthException("Database Error",ErrorCode::DATABASE_ERROR->value);
        }
        catch (\Exception $e) {
            throw new SimpleAuthException("Database Error",ErrorCode::DATABASE_ERROR->value, $e);
        }
        if(is_null($this->Status::tryFrom(0)) || $this->Status::tryFrom(0)->name !== "UNKNOWN")
            throw new SimpleAuthException("Status Enum must have UNKNOWN with a value of 0",
                ErrorCode::INVALID_STATUS_ENUM->value);
        if(is_null($this->Role::tryFrom(0)) || $this->Role::tryFrom(0)->name !== "UNKNOWN")
            throw new SimpleAuthException("Roles Enum must have UNKNOWN with a value of 0",
                ErrorCode::INVALID_ROLE_ENUM->value);
        echo "<h1>Welcome To Simple Auth!</h1><br>";

    }

    public function lookupUsername(string $username){
        unset($this->User, $this->authenticated);
        $stmt = $this->Connection->prepare("SELECT * FROM users WHERE user_name =?;");
        $stmt->execute([$username]);
        $this->User = match($stmt->rowCount()){
            0 => throw new SimpleAuthException("User Not Found", ErrorCode::USERNAME_NOT_FOUND->value),
            1 => $stmt->fetchAll(PDO::FETCH_CLASS,\SimpleAuth\UserDTO::class),
            default => throw new SimpleAuthException("Username not unique", ErrorCode::USERNAME_NOT_UNIQUE->value),
        };
        $this->User = $this->User[0];
        $this->User->enumerate($this->Status, $this->Role);
        $this->User->user_status = STATUS::tryFromName($this->User->user_status) ?? $this->Status::UNKNOWN;
        $this->User->user_role = ROLE::tryFromName($this->User->user_role) ?? $this->Role::UNKNOWN;
        return $this;
    }

    use lookupUserName;

    public function authenticateWithPassword(string $password): Authenticate{
        if ($this->User->user_status->value > 0) {
            if(password_verify($password,$this->User->user_password)){
                $this->authenticated = true;
                return $this;
            } else {
            throw new SimpleAuthException("Authentication Failed", ErrorCode::PASSWORD_AUTHENTICATION_FAILED->value);
            }
        } else {
            throw new SimpleAuthException(
                "User " . $this->User->user_id . " tried to authenticate but is " . $this->User->user_id->name . ".",
                ErrorCode::USER_STATUS_ERROR->value);
        }
    }

    public function isAuthenticated(): bool{
        return $this->authenticated ?? false;
    }

    public function getUser(){
        return $this->User;
    }
}
