<?php

declare(strict_types=1);

namespace SimpleAuth;

use \BackedEnum;
use \DateTime;
use Error;
use \Exception;
use \PDO;
use PDOException;
use \SimpleAuth\UserDTO;
use \SimpleAuth\Enums\Status;
use \SimpleAuth\Enums\Role;
use \SimpleAuth\Enums\ErrorCode;
use \SimpleAuth\Throwable\SimpleAuthException;


class Authenticate
{
    public const array REQUIRED_FIELDS = ['user_name', 'user_email', 'user_hashed_password'];
    public UserDTO $User;
    private bool $authenticated;


    public function __construct(private PDO $Connection, private $Status = Status::class, private $Role = Role::class){
        try{
            if(is_null($this->Connection->getAttribute(PDO::ATTR_CONNECTION_STATUS)))
                throw new SimpleAuthException(
                    ErrorCode::DATABASE_ERROR->message(),
                    ErrorCode::DATABASE_ERROR->value);
        }
        catch (\Exception $e) {
            throw new SimpleAuthException(
                ErrorCode::DATABASE_ERROR->message(),
                ErrorCode::DATABASE_ERROR->value, 
                $e);
        }
        $Connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->validateEnum($this->Status,['UNKNOWN']);
        $this->validateEnum($this->Role,['UNKNOWN']);
    }
    #region Authentication Methods
    public function authenticateWithPassword(string $password): Authenticate{
        if ($this->User->user_status->value > 0) {
            if(password_verify($password,$this->User->user_hashed_password)){
                $this->authenticated = true;
                return $this;
            } else {
            throw new SimpleAuthException(
                ErrorCode::PASSWORD_AUTHENTICATION_FAILED->message(),
                ErrorCode::PASSWORD_AUTHENTICATION_FAILED->value);
            }
        } else {
            throw new SimpleAuthException(
                "User " . $this->User->user_id . " tried to authenticate but is " . 
                          $this->User->user_status->name . ".",
                ErrorCode::USER_STATUS_ERROR->value);
        }
    }

    public function authenticateWithValidator(string $validator): Authenticate{
        if ($this->User->user_status->value > 0) {
            if(password_verify($validator,$this->User->user_cookie_validator)){
                $this->authenticated = true;
                return $this;
            } else {
            throw new SimpleAuthException(
                ErrorCode::AUTHENTICATION_FAILED->message(),
                ErrorCode::AUTHENTICATION_FAILED->value);
            }
        } else {
            throw new SimpleAuthException(
                "User " . $this->User->user_id . " tried to authenticate but is " . 
                          $this->User->user_status->name . ".",
                ErrorCode::USER_STATUS_ERROR->value);
        }
    }

    public function authenticateResetToken(string $token){
        if($token === $this->User->user_password_reset_token){
            if(time() <= strtotime($this->User->user_password_reset_timestamp)){
                $this->authenticated = true;
                return $this;
            }
        }
        return $this;
    }
    #endregion

    #region Chain Openers
    public function newUser(){
        unset($this->User, $this->authenticated);
        $this->User = new UserDTO();
        return $this;
    }

    public function editUser(int $userID){
       unset($this->User);
       $this->User = new UserDTO;
       $this->User->user_id = $userID;
       return $this;
    }
    #endregion
    
    #region Write To Database
    public function insertIntoDatabase(){
        $userArray = $this->User->toArrayNoID();
        $this->missingRequiredFields($userArray);
        $keys      = array_keys($userArray);
        $set       = implode(", ",$keys);
        $values    = implode(", :",$keys);
        $sql       = "INSERT INTO users (" . $set . ") VALUES (:" . $values . ")";
        $this->toDatabase($sql, $userArray);
        return $this;
    }

    public function updateDatabase() {
        if(is_null($this->User->user_id))
            throw new SimpleAuthExceptionException(ErrorCode::NO_USER_SELECTED->message(),ErrorCode::NO_USER_SELECTED->value);        
        $userArray = $this->User->toArrayNoID();
        $this->missingRequiredFields($userArray);
        foreach(array_keys($userArray) as $key)
            $setArray[] = "$key = :$key";
        $set = implode(", ", $setArray);        
        $sql = "UPDATE users SET $set WHERE user_id = " . $this->getUserID() . ";";        
        $this->toDatabase($sql, $userArray);   
        return $this;
    }
    #endregion
    
    #region Lookup Methods
    //TODO:convert Process Results into "fromDatabase" to generate all possible errors
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

    public function lookupCookie(string $selector): Authenticate{
        unset($this->User, $this->authenticated);
        $stmt = $this->Connection->prepare("SELECT * FROM users WHERE user_cookie_selector =?;");
        $stmt->execute([$selector]);
        $this->processResult($stmt);
        return $this;
    }

    public function lookupResetToken(string $token): Authenticate{
        unset($this->User, $this->authenticated);
        $stmt = $this->Connection->prepare("SELECT * FROM users WHERE user_password_reset_token =?;");
        $stmt->execute([$token]);
        $this->processResult($stmt);
        return $this;
    }
    #endregion

    #region Getter Methods
    public function getUser()                   : ?UserDTO { return ($this->User instanceof UserDTO) ? $this->User : null; }
    public function getUserID()                 : ?int     {return $this->User->user_id;}
    public function getUserName()               : ?string  {return $this->User->user_name;}
    public function getEmail()                  : ?string  {return $this->User->user_email;}
    public function getHashedPassword()         : ?string  {return $this->User->user_hashed_password;}
    public function getCreatedAt()              : ?string  {return $this->User->user_created;}
    public function getPermissions()            : ?int     {return $this->User->user_permissions;}
    public function getCookieSelector()         : ?string  {return $this->User->user_cookie_selector;}
    public function getCookieValidator()        : ?string  {return $this->User->user_cookie_validator;}
    public function getPasswordResetToken()     : ?string  {return $this->User->user_cookie_validator;}
    public function getPasswordResetTimestamp() : ?string  {return $this->User->user_cookie_validator;}
    public function isAuthenticated()           : bool     {return $this->authenticated ?? false;}
    public function getStatus()  : null|string|BackedEnum  {return $this->User->user_status;}
    public function getRole()    : null|string|BackedEnum  {return $this->User->user_role;}
    #endregion

    #region Setter Methods
    public function setUser(UserDTO $User){
        $this->User = $User;
        return $this;
    }
    public function setUserName(string $username){
        $this->User->user_name = $username;
        return $this;
    }
    public function setEmail(string $email) {
        $this->User->user_email = $email;
        return $this;
	}
    public function setHashedPassword(string $hashedPassword) {
        $this->User->user_hashed_password = $hashedPassword;
        return $this;
	}
    public function setPermissions(int $permissions) {
        $this->User->user_permissions = $permissions;
        return $this;
	}
    public function setDKP(int $dkp) {
        $this->User->user_dkp = $dkp;
        return $this;
	}
    public function setCreatedAt(string $timestamp) {
        $this->User->user_created = $timestamp;
        return $this;
	}
    public function setStatus(string $status) {
        if(is_null($this->Status::tryFromName(strtoupper($status))))
            throw new SimpleAuthException("Status " . $status . " not valid.",
                                             ErrorCode::USER_STATUS_ERROR->value);
        $this->User->user_status = $this->Status::tryFromName(strtoupper($status));
        return $this;
	}
    public function setSelector(?string $selector) {
        $this->User->user_cookie_selector = $selector;
        return $this;
	}
    public function setValidator(?string $validator) {
        $this->User->user_cookie_validator = $validator;
        return $this;
	}
    public function setResetToken(?string $token) {
        $this->User->user_password_reset_token = $token;
        return $this;
    }
    public function setResetTokenTimestamp(?string $timestamp) {
        $this->User->user_password_reset_timestamp = $timestamp;
        return $this;
    }
    public function setRole(string $role) {
        if(is_null($this->Role::tryFromName(strtoupper($role))))
            throw new SimpleAuthException("Role " . $role . " not valid.",
                                             ErrorCode::USER_STATUS_ERROR->value);
        $this->User->user_role = $this->Role::tryFromName(strtoupper($role));
        return $this;
	}

    #endregion

    #region Private Methods
    private function exists(string $column, string $value) {
        $stmt = $this->Connection->prepare("SELECT * FROM users WHERE $column =?;");
        $stmt->execute([$value]);
        return ($stmt->rowCount() > 0) ? true : false;
    }

    private function processResult(\PDOStatement $stmt){
        $userArray = match($stmt->rowCount())
        {
            0 => throw new SimpleAuthException(ErrorCode::USERNAME_NOT_FOUND->message(), ErrorCode::USERNAME_NOT_FOUND->value),
            1 => $stmt->fetchAll(PDO::FETCH_CLASS,\SimpleAuth\UserDTO::class),
            default => throw new SimpleAuthException(ErrorCode::DATABASE_ERROR->message(),ErrorCode::DATABASE_ERROR->value),
        };

        if(sizeof($userArray) === 1)
        {
            $this->User = $userArray[0];
            $this->User->enumerate($this->Status, $this->Role);
            return true;
        }
        return false;
    }
    
    private function validateEnum(string $enumClass, array $requiredCases){
        foreach($requiredCases as $case){
            if(is_null($enumClass::tryFromName($case)))
                throw new SimpleAuthException(
                    $enumClass . " missing required cases ( " . implode(", ", $requiredCases) . " )", 
                    ErrorCode::INVALID_ENUM->value);
            return true;
        }
    }

    private function missingRequiredFields(array $array){
        foreach($this::REQUIRED_FIELDS as $field) {
            if(key_exists($field,$array) && !is_null($array[$field]))
            {
                continue;
            }
            else 
            {
                throw new SimpleAuthException(ErrorCode::MISSING_REQUIRED_FIELD->message(),
                                                 ErrorCode::MISSING_REQUIRED_FIELD->value);
            }
        }
        return (isset($error)) ? true : false;
    }

    private function toDatabase(string $sql, array $params): void {
        $stmt = $this->Connection->prepare($sql);
        try 
        {
            $stmt->execute($params);            
        } 
        catch (PDOException $e) 
        {
                $errorInfo    = $e->errorInfo;
                $errorType    = (int)$errorInfo[0];
                $errorCode    = (int)$errorInfo[1];
                $errorMessage = $errorInfo[2];
                if($errorType = 23000){
                    $error        = match (true) {
                        (bool)preg_match("/user_name/",$errorMessage)  => ErrorCode::USERNAME_NOT_UNIQUE,
                        (bool)preg_match("/user_email/",$errorMessage) => ErrorCode::EMAIL_NOT_UNIQUE,
                        (bool)preg_match("/cookie/",$errorMessage)     => ErrorCode::SELECTOR_NOT_UNIQUE,
                        default                                                         => ErrorCode::USER_DATA_ERROR,
                    };
                    throw new SimpleAuthException($error->message(), $error->value);
                } else {
                throw $e;
            }
        }
    }
    #endregion
}
