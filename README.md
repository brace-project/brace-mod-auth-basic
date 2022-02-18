# brace-mod-auth-basic
HTTP Basic Authentication



## Example

```php
$app->pipe->addMiddleWare(
    new \Brace\Auth\Basic\AuthBasicMiddleware(
        function (\Brace\Auth\Basic\BasicAuthToken $basicAuthToken) {
            return $basicAuthToken->user === "admin" && $basicAuthToken->passwd === "test"
        }
    )
)
```

Dont't forget to call

```php
$basicAuthToken->validate();
```

To verify the Token is valid
