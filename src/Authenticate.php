<?php
declare(strict_types=1);

namespace SimpleAuth;

use Exception;
use PDO;

Class Authenticate {

    private array $User;
    private bool $authenticated;

    public function __construct(private PDO $Connection){
        echo "<h1>Welcome To Simple Auth 0.0.3!</h1><br>";
    }

    public function lookupUsername(string $username){
        unset($this->User);
        $stmt = $this->Connection->prepare("SELECT * FROM users WHERE user_name =?;");
        $stmt->execute([$username]);
        $this->User = match($stmt->rowCount()){
            0 => throw new Exception("User Not Found"),
            1 => $stmt->fetch(PDO::FETCH_ASSOC),
            default => throw new Exception("Username not unique"),
        };
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
        if(password_verify($password,$this->User['user_password'])){
            $this->authenticated = true;
            return $this;
        }
        throw new Exception("Authentication Failed");
    }

    public function isAuthenticated(): bool{
        return $this->authenticated ?? false;
    }

    public function getUser(){
        return $this->User;
    }
}
