<?php

declare(strict_types=1);

namespace SimpleAuth\Traits;

trait lookupUserName
{
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
}
