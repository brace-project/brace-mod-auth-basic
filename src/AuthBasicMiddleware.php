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


    public function __construct(
        private AuthValidatorInterface|null $validator=null,
        private bool $required = false
    ){}



    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Default: Return empty user (validate() will throw AuthRequired Exception)
        $this->app->define("basicAuthToken", new DiValue(new BasicAuthToken([
                "user" => null,
                "passwd" => null,
                "valid" => null,
                "hasCredentials" => false
            ])
        ));

        $serverParams = $request->getServerParams();
        try {
            if (isset ($serverParams["PHP_AUTH_USER"])) {
                $basicAuthToken = new BasicAuthToken([
                    "user" => $serverParams["PHP_AUTH_USER"],
                    "passwd" => $serverParams["PHP_AUTH_PW"] ?? null,
                    "valid" => null,
                    "hasCredentials" => true
                ]);
                if ($this->validator !== null) {
                    $basicAuthToken = $this->validator->validate($basicAuthToken, $this->app);
                    $basicAuthToken->validate();
                }
                $this->app->define("basicAuthToken", new DiValue($basicAuthToken));
            } else {
                if ($this->required)
                    throw new AuthorizationRequiredException("Authorization is required for this endpoint");
            }

            return $handler->handle($request);
        } catch (AuthorizationRequiredException $ex) {
            // Request authentication if not present
            return new TextResponse("401 Authentication required: {$ex->getMessage()}", 401, [
                "WWW-Authenticate" => "Basic realm=\"\""
            ]);
        }

    }
}
