<?php


namespace Brace\Auth\Basic;


use Brace\Core\Helper\Immutable;

/**
 * Class BasicAuthToken
 * @package Brace\Auth\Basic
 *
 * @property-read string $user
 * @property-read string|null $passwd
 * @property-read bool $valid
 * @property-read bool $hasCredentials
 * @property-read string[] $scopes
 * @property-read array $meta
 */
class BasicAuthToken extends Immutable
{

    public function validate()
    {
        if ($this->user === null)
            throw new AuthorizationRequiredException("No basic auth user present");
        if ($this->valid !== true)
            throw new AuthorizationRequiredException("Basic authentication invalid");
    }

}
