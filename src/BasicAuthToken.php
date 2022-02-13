<?php


namespace Brace\Auth\Basic;


use Brace\Core\Helper\Immutable;

/**
 * Class BasicAuthToken
 * @package Brace\Auth\Basic
 *
 * @property-read string $user
 * @property-read string|null $passwd
 */
class BasicAuthToken extends Immutable
{

    public function validate()
    {
        if ($this->user === null)
            throw new AuthorizationRequiredException("No baisc auth user present");
    }
}