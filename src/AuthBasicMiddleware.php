<?php


namespace Brace\Auth\Basic;


use Brace\Core\Base\BraceAbstractMiddleware;
use Laminas\Diactoros\Response\TextResponse;
use Phore\Di\Container\Producer\DiProducer;
use Phore\Di\Container\Producer\DiValue;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AuthBasicMiddleware extends BraceAbstractMiddleware
{




    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Default: Throw Authorization Required Exception and catch it in the middleware
        $this->app->define("basicAuthToken", new DiProducer(function () {
            throw new AuthorizationRequiredException();
        }));

        $userInfo = $request->getUri()->getUserInfo();
        if ($userInfo !== "") {
            $parts = explode(":", $userInfo, 2);
            $basicAuthToken = new BasicAuthToken([
                "user" => $parts[0],
                "passwd" => $parts[1] ?? null
            ]);
            $this->app->define("basicAuthToken", new DiValue($basicAuthToken));
        }

        // Catch the exception if authtoken was requested somewhere
        try {
            return $handler->handle($request);
        } catch (AuthorizationRequiredException $ex) {
            // Request authentication if not present
            return new TextResponse("401 Authentication required", 401, [
                "WWW-Authenticate" => "Basic realm=\"My Realm\""
            ]);
        }

    }
}