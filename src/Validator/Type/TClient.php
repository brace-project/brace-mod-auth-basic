<?php

namespace Brace\Auth\Basic\Validator\Type;

class TClient
{
    public function __construct(



        /**
         * @var string
         */
        public $client_id,

        /**
         * @var string[]
         */
        public $access_secrets,

        /**
         * @var string[]|null
         */
        public array|null $scopes = [],

        /**
         * @var array|null
         */
        public array|null $meta = [],

        /**
         * @var bool|null
         */
        public $active = true
    ){}
}
