<?php

declare(strict_types=1);

namespace SimpleAuth\Throwable;

use Throwable;
use Exception;


Class SimpleAuthException extends Exception
{

    public function __construct(public $message = "", public $code = 0, public Throwable|null $previous = null)
    {
        $this->throw();
    }

    public function throw(){
        parent::__construct($this->message,$this->code, $this->previous);
    }
}

