<?php

namespace Brace\Auth\Basic\Validator;

use Brace\Auth\Basic\AuthorizationRequiredException;
use Brace\Auth\Basic\AuthValidatorInterface;
use Brace\Auth\Basic\BasicAuthToken;
use Brace\Core\BraceApp;
use Lack\Subscription\Type\T_Subscription;

class SubscriptionAuthValidator implements AuthValidatorInterface
{

    public function validate(BasicAuthToken $basicAuthToken, BraceApp $app): BasicAuthToken
    {
        if (! class_exists(T_Subscription::class))
            throw new \InvalidArgumentException("BasicAuthMiddleware: T_Subscription class not found");

        $subscription = $app->get("subscription", T_Subscription::class);
        $privateConfig = $subscription->getClientPrivateConfig();

        if ( ! isset ($privateConfig["auth"]))
            throw new \InvalidArgumentException("BasicAuthMiddleware: Missing 'auth' in subscription client private config");

        $auth = $privateConfig["auth"];

        if ( ! validate_auth($basicAuthToken->user, $basicAuthToken->passwd, $auth))
            throw new AuthorizationRequiredException("Invalid credentials");


        $basicAuthToken = new BasicAuthToken([
            "user" => $basicAuthToken->user,
            "passwd" => $basicAuthToken->passwd,
            "valid" => true,
            "hasCredentials" => true
        ]);

        return $basicAuthToken;
    }

}
