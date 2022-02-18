<?php

namespace Brace\Auth\Basic\Validator;

use Brace\Auth\Basic\AuthValidatorInterface;
use Brace\Auth\Basic\BasicAuthToken;
use Brace\Core\BraceApp;

class LambdaAuthValidator implements AuthValidatorInterface
{

    public function __construct(
        private \Closure $validator
    ){}

    public function validate(BasicAuthToken $basicAuthToken, BraceApp $app): BasicAuthToken
    {
        $return = phore_di_call($this->validator, $app, [
            "basicAuthToken" => $basicAuthToken
        ]);
        if ( ! is_bool($return))
            throw new \InvalidArgumentException("BasicAuthMiddleware: Validator Closure must return boolean value");
        if ($return === true) {
            $basicAuthToken = new BasicAuthToken([
                "user" => $basicAuthToken->user,
                "passwd" => $basicAuthToken->passwd,
                "valid" => true,
                "hasCredentials" => true
            ]);
        }
        return $basicAuthToken;
    }
}
