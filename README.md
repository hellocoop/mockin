# mock server

- < intro >
- < info on https://mock.hello.dev - can use https://playground.hello.dev to test out >
- < Docker Hub image >

## Environment Parameters

- `HELLO_MOCK_ISSUER` - the issuer URL the mock server is acting as. Defaults to http://localhost
- `HELLO_MOCK_PORT` - the port the server listens on. Defaults to 8080
- `HELLO_MOCK_CLIENT_ID` - if provided, the mock server will only accept this as a valid client_id. If not set, any client_id value passed is valid
- `HELLO_MOCK_CLIENT_SECRET` - if provided, the mock server will only accept this as a valid client_secret. If not set, any value is valid.
- `HELLO_MOCK_REDIRECT_URI` - if provided, the mock server will accept this as a valid redirect_uri. If not set, any redirect_uri value passed is valid

### Internal

- `HELLO_MOCK_OAUTH` - if set, the mock server will accept an OAuth flow to generate access tokens to the console server. Valid parameters are `console` and `quickstart`

## Endpoints

    /.well-known/openid-configuration

which defines the following endpoints

    /authorize
    /oauth/token
    /oauth/introspection
    /oauth/userinfo
    /jwks
    
 # Another mocking signal
 
 /mock?fixture=JSON
    
  ????

## OIDC Flows

The mock server supports `id_token` and `code` response types (flows) per the openid-configuration

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

### Limitations

As the mock server stores state in memory, only one instance should be run in an environment.
