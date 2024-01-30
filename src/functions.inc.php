<?php


/**
 * @param $username
 * @param $password
 * @param string[] $authData       Array of "username:crypted password" pairs (if password part is missing - ignore line)
 * @return bool
 */
function validate_auth(string $username, string $password, array $authData) : bool
{
    foreach ($authData as $authLine) {
        $authLine = trim($authLine);
        if (empty($authLine))
            continue;
        if (strpos($authLine, ":") === false) {
            continue;
        }
        [$authUser, $authPasswd] = explode(":", $authLine, 2);
        if ($authUser === $username && crypt($password, $authPasswd) === $authPasswd)
            return true;
    }
    return false;
}
