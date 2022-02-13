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
        // Default: Return empty user (validate() will throw AuthRequired Exception)
        $this->app->define("basicAuthToken", new DiValue(new BasicAuthToken([
                "user" => null,
                "passwd" => null
            ])
        ));

        $serverParams = $request->getServerParams();

        if (isset ($serverParams["PHP_AUTH_USER"])) {
            $basicAuthToken = new BasicAuthToken([
                "user" => $serverParams["PHP_AUTH_USER"],
                "passwd" => $serverParams["PHP_AUTH_PW"] ?? null
            ]);
            $this->app->define("basicAuthToken", new DiValue($basicAuthToken));
        }

        // Catch the exception if authtoken was requested somewhere
        try {
            return $handler->handle($request);
        } catch (AuthorizationRequiredException $ex) {
            // Request authentication if not present
            return new TextResponse("401 Authentication required", 401, [
                "WWW-Authenticate" => "Basic realm=\"\""
            ]);
        }

    }
}