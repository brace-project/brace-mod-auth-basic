<?php

namespace Brace\Auth\Basic\Validator;

use Brace\Auth\Basic\AuthorizationRequiredException;
use Brace\Auth\Basic\AuthValidatorInterface;
use Brace\Auth\Basic\BasicAuthToken;
use Brace\Auth\Basic\Validator\Type\TAuthConfig;
use Brace\Core\BraceApp;

class ClientIdFileAuthValidator implements AuthValidatorInterface
{

    /**
     * @var \Phore\FileSystem\PhoreFile
     */
    private $file;

    public function __construct(string $file) {
        $this->file = phore_file($file);
    }


    public function validate(BasicAuthToken $basicAuthToken, BraceApp $app): BasicAuthToken
    {
        $this->file->assertFile();
        $authConfig = $this->file->get_yaml(TAuthConfig::class);
        assert($authConfig instanceof TAuthConfig);

        foreach ($authConfig->clients as $client) {
            if ($client->client_id !== $basicAuthToken->user) {
                continue;
            }
            if ($client->active === false)
                throw new AuthorizationRequiredException("Client_id '{$client->client_id}' is not active");
            foreach ($client->access_secrets as $secret) {
                if (password_verify($basicAuthToken->passwd, $secret)) {
                    return new BasicAuthToken([
                        "user" => $basicAuthToken->user,
                        "passwd" => $basicAuthToken->passwd,
                        "valid" => true,
                        "hasCredentials" => true,
                        "scopes" => $client->scopes ?? [],
                        "meta" => $client->meta ?? []
                    ]);
                }
            }
        }
        return $basicAuthToken;
    }
}
