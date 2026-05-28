<?php

declare(strict_types=1);

namespace SimpleAuth\Throwable;

use Throwable;
use Exception;


Class SimpleAuthException extends Exception {

    public function __construct(public $messsage = "", public $code = 0, public Throwable|null $previous = null)
    {
                
    }

    public function throw(){
        parent::__construct($this->message,$this->code, $this->previous);
    }

}

