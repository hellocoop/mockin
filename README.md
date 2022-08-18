# mock server

- intro
- info on https://mock.hello.dev
- Docker Hub image

## Environment Parameters

`HELLO_MOCK_HOST` - where the mock server is running, which is also the issuer URL

## Endpoints

    /.well-known/openid-configuration

which defines the following endpoints

    /authorize
    /oauth/token
    /oauth/introspection
    /oauth/userinfo
    /jwks

## OIDC 

## Fixtures

Folder containing responses 

## Mocking different users

`fixture/default.json` is the default user profile

passing an extra parameter of `mock=user1` would return the user profile in `fixture/user1.json`

## Contributions
