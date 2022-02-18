<?php

namespace Brace\Auth\Basic;

use Brace\Core\BraceApp;

interface AuthValidatorInterface
{

    /**
     * @param BasicAuthToken $basicAuthToken
     * @return BasicAuthToken
     */
    public function validate(BasicAuthToken $basicAuthToken, BraceApp $app) : BasicAuthToken;
}
