<?php
declare(strict_types=1);

namespace SimpleAuth;

use PDO;
use PDOStatement;
use SimpleAuth\Enums\ErrorCode;
use SimpleAuth\Enums\Status;
use SimpleAuth\Enums\Role;
use SimpleAuth\Throwable\SimpleAuthException;

Class Authenticate {

    private UserDTO|array $User;
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
        $this->processResult($stmt);
        return $this;
    }

    public function lookupUserID(int $userID){
        unset($this->User, $this->authenticated);
        $stmt = $this->Connection->prepare("SELECT * FROM users WHERE user_id =?;");
        $stmt->execute([$userID]);
        $this->processResult($stmt);
        return $this;        
    }

    public function lookupEmail(string $email){
        unset($this->User, $this->authenticated);
        $stmt = $this->Connection->prepare("SELECT * FROM users WHERE user_email =?;");
        $stmt->execute([$email]);
        $this->processResult($stmt);
        return $this;  
    }

    private function processResult(PDOStatement $stmt){
        $userArray = match($stmt->rowCount())
        {
            0 => throw new SimpleAuthException("User Not Found", ErrorCode::USERNAME_NOT_FOUND->value),
            1 => $stmt->fetchAll(PDO::FETCH_CLASS,\SimpleAuth\UserDTO::class),
            default => throw new SimpleAuthException("Username not unique", ErrorCode::USERNAME_NOT_UNIQUE->value),
        };
        
        if(sizeof($userArray) == 1)
        {
            $this->User = $userArray[0];
            $this->User->enumerate($this->Status::class, $this->Role::class);
            $this->User->user_status = $this->Status::tryFromName($this->User->user_status) ?? $this->Status::UNKNOWN;
            $this->User->user_role = $this->Role::tryFromName($this->User->user_role) ?? $this->Role::UNKNOWN;
            return true;
        }

        return false;
    }

    public function changePassword(string $newPassword): Authenticate{
        if(is_null($this->User))
            throw new SimpleAuthException("No user selected",ErrorCode::NO_USER_SELECTED->value);
        $newPassword = password_hash($newPassword,PASSWORD_DEFAULT);
        $stmt = $this->Connection->prepare("UPDATE users SET user_password = ? WHERE user_id = ?;");
        $stmt->execute([$newPassword, $this->User->user_id]);
        $result = $stmt->rowCount();
        $this->User->user_password = $newPassword;
        return $this;    
    }

    public function updateUser(UserDTO $User): void {
        
        //TODO: Implement updateUser
    }

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
                "User " . $this->User->user_id . " tried to authenticate but is " . $this->User->user_status->name . ".",
                ErrorCode::USER_STATUS_ERROR->value);
        }
    }

    public function isAuthenticated(): bool {
        return $this->authenticated ?? false;
    }

    public function getUser(): ?UserDTO {
        return ($this->User instanceof UserDTO) ? $this->User : null;
    }
}
