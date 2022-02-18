# brace-mod-auth-basic
HTTP Basic Authentication



## Example

## Validate against closure function

```php
$app->pipe->addMiddleWare(
    new AuthBasicMiddleware(new \Brace\Auth\Basic\Validator\LambdaAuthValidator(
        function (\Brace\Auth\Basic\BasicAuthToken $basicAuthToken) {
            return $basicAuthToken->user === "client1" && $basicAuthToken->passwd === "test";
        }
    ))
);
```

## Validate against File
```php
$app->pipe->addMiddleWare(
    new AuthBasicMiddleware(new ClientIdFileAuthValidator(CONFIG_PATH . "/clients.yml"))
);
```
- [clients.yml demo](demo/clients.yml)

Dont't forget to call

```php
$basicAuthToken->validate();
```

To verify the Token is valid
