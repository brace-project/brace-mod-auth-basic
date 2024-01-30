<?php

namespace Brace\Auth\Basic;

use Brace\Core\Base\BraceAbstractMiddleware;
use Phore\Di\Container\Producer\DiValue;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;


/**
 * Class SimpleBasicAuthMiddleware
 *
 * This middleware is a simple implementation of BasicAuth.
 * <example>
 *      $settingsValidator = new SimpleBasicAuthMiddleware(function (BasicAuthToken $authToken) {
 *          return $authToken->user === "admin" && $authToken->passwd === "admin";
 *      });
 *      $app->router->registerClass($mount, AccountSettingsCtrl::class, [$settingsValidator]);
 * </example>
 */class SimpleBasicAuthMiddleware extends BraceAbstractMiddleware
{

    public function __construct(


        /**
         * A authenticator function that takes BasicAuthToken (name: authToken) as argument and returns true if the token is valid
         *
         * <example>
         *     function (BasicAuthToken $authToken) : bool {
         *          if ($authToken->user === "admin" && $authToken->passwd === "secret")
         *            return true;
         *         return false;
         *    }
         * </example>
         *
         * @var \Closure|null
         */
        private ?\Closure $authenticator = null,

        /**
         *
         * A array of "username:cryptedPassword" strings
         *
         * @var string[]|null
         */
        private ?array $allowUsers = null,
        private string $realm = "Private API",
    ) {
        if ($this->authenticator === null && $this->allowUsers !== null) {
            $this->authenticator = function (BasicAuthToken $authToken) : bool {
                return validate_auth($authToken->user, $authToken->passwd, $this->allowUsers);
            };
        }
        if ($this->authenticator === null && $this->allowUsers === null)
            throw new \InvalidArgumentException("Either authenticator or allowUsers must be set");
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $__authTokenTemp = new BasicAuthToken([
            "user" => $request->getServerParams()["PHP_AUTH_USER"] ?? null,
            "passwd" => $request->getServerParams()["PHP_AUTH_PW"] ?? null,
            "valid" => null,
            // if user is set, we have credentials
            "hasCredentials" => $request->getServerParams()["PHP_AUTH_USER"] ?? null !== null
        ]);

        $authToken = new BasicAuthToken([
            "user" => $__authTokenTemp->user,
            "passwd" => $__authTokenTemp->passwd,

            // Attention: Validation happens here!
            "valid" => phore_di_call($this->authenticator, $this->app, ["authToken" => $__authTokenTemp]) === true ? true : false,

            "hasCredentials" => $__authTokenTemp->hasCredentials
        ]);

        $this->app->define("basicAuthToken", new DiValue($authToken));

        if ($authToken->valid !== true) {
            return $this->app->responseFactory->createResponseWithBody("401 Authentication required", 401, [
                "WWW-Authenticate" => "Basic realm=\"{$this->realm}\""
            ]);
        }

        return $handler->handle($request);
    }

}
