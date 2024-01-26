<?php

namespace Brace\Auth\Basic;

use Brace\Core\Base\BraceAbstractMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class RequireValidAuthTokenMiddleware extends BraceAbstractMiddleware
{

    public function __construct(

    ) {
    }


    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $authToken = $this->app->get("basicAuthToken", BasicAuthToken::class);

        $authToken->validate();
        return $handler->handle($request);
    }
}
