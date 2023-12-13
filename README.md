# mock server

- < intro >
- < info on https://mock.hello.dev - can use https://playground.hello.dev to test out >
- < Docker Hub image >

## Defaults

### client
- any id and redirect URI is accepted

### token
```json
header
{

}
payload
{
    
}
```

### set

```json
header
{

}
payload
{

}
```



## Mock API

PUT /mock/authorize 
    ?error=
    ?wildcard_domain=
    ?state=
DELETE /mock/authorize

PUT /mock/oauth/token
    ?status= 
    ?error= 
DELETE /mock/oauth/token

PUT /mock/oauth/introspection
    ?status= 
    ?error= 
DELETE /mock/oauth/introspection

PUT /mock/oauth/userinfo
    ?status= 
    ?error= 
DELETE /mock/oauth/userinfo

PUT /mock/token
        ?wrong_key
        ?invalid_key
        ?wrong_alg
    { 
        header
        payload
            value: false - will not be returned
    }
DELETE /mock/token

PUT /mock/user
    // shorthand for /mock/token {payload}
DELETE /mock/user

PUT /mock/invite
    ?error
DELETE /mock/invite

PUT /mock/set
    {
        header
        payload
    }
DELETE /mock/set

## Sample Test Suite



## Environment Parameters

- `HELLO_MOCK_ISSUER` - the issuer URL the mock server is acting as. Defaults to http://localhost (cannot be `https://issuer.hello.coop` or `https://wallet.hello.coop`)
- `HELLO_MOCK_PORT` - the port the server listens on. Defaults to 8080

- `SEC_EVENT`

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
    
 ### Changing mock response
 
 
 `PUT /mock` JSON fixture file
 
 or
 
 `PUT /mock?error=AUD_ERROR`
  

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

    USER_CANCEL

    AUD_ERROR
    ISS_ERROR
    NONCE_ERROR
    INVALID_JWT
    INVALID_JWT_HEADER
    INVALID_JWT_PAYLOAD
    503_ERROR

### Limitations

As the mock server stores state in memory, only one instance should be run in an environment.

# Alternative Mock Servers

## Duende Software 
Free for personal use only
https://github.com/Soluto/oidc-server-mock

## MockOIDC
https://github.com/oauth2-proxy/mockoidc

## Xpirit Writeup
https://xpirit.com/mock-your-openid-connect-provider/

## Wire Mock
Freemium Service
https://docs.wiremock.io/oauth2-mock/
