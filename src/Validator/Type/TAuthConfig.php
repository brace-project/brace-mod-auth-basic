<?php

namespace Brace\Auth\Basic\Validator\Type;

class TAuthConfig
{
    public function __construct(

        /**
         * @var TClient[]
         */
        public array $clients
    ){}
}
