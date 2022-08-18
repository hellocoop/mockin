# mock server

- < intro >
- < info on https://mock.hello.dev - can use https://playground.hello.dev to test out >
- < Docker Hub image >

## Environment Parameters

`HELLO_MOCK_ISSUER` - where the mock server is running include the port if not running on 80 for HTTP or 443 for HTTPS
`HELLO_MOCK_CLIENT_ID` - if set, mock server will only accept this as the client_id value
`HELLO_MOCK_REDIRECT_URI` - if set, the mock server will only redirect to this redirect_uri
`HELLO_MOCK_OAUTH` - quickstart or 


## Endpoints

    /.well-known/openid-configuration

which defines the following endpoints

    /authorize
    /oauth/token
    /oauth/introspection
    /oauth/userinfo
    /jwks

## OIDC 


## Mock Responses

passing a `mock` parameter in the request query string will change the response from the server

### User Claims

`fixture/DEFAULT.json` is the default user profile - IE no `mock` value passed

passing an extra parameter of `mock=user1` would return the user profile in `fixture/user1.json`

add other files to the `fixtures` folder for other responses

TBD: describe how to do that with the Docker Image

### Errors

    AUD_ERROR
    ISS_ERROR
    NONCE_ERROR
    INVALID_JWT
    INVALID_JWT_HEADER
    INVALID_JWT_PAYLOAD
    503_ERROR
