# mock server

## Installation

## Configuration

- `IP` - IP that *mockin* will listen on. Defaults to `127.0.0.1`
- `PORT` - port that *mockin* will listen on. Defaults to `3333`
- `ISSUER` - Issuer that *mockin* will use as the `iss` value. Defaults to `http:${IP}:${PORT}` which is `http://127.0.0.1:3333` if other defaults are used. Note that the ISSUER value does not need to be the same as IP:PORT, and can be any value except the production ISSUER value (`https://issuer.hello.coop`). It needs to be an address that will resolve to *mockin* if your app is fetching up `ISSUER/.well-known/openid-configuration`

- `client_id` - you can pass any value

If you are using one of the SDKs from https://github.com/hellocoop/packages you set `HELLO_WALLET` to be where the browser and server can reach *mockin* which is `http://127.0.0.1:3333` by default.

## Mockin & Playground
If you run `npx @hellocoop/mockin` using the defaults and then in https://playground.hello.dev add `http://127.0.0.1:3333/authorize` as an Authorization Server, you can play with the different parameters and see the responses returned. You can make `curl` commands to *mockin* to set mock return values. For example 
```
curl -X PUT "http://127.0.0.1:3333/mock/authorization?error=access_denied" 
```
will return the current value of MOCK and when using Playground will return the `access_denied` error as if the user had denied access.


### Using Docker Image

`npm i -D @hellocoop/mockin`
`npx mockin`

## Defaults

### client
- any id and redirect URI is accepted

## Mock API

PUT /mock/token
    ?iss=
    ?aud=
    ?expired=true
    ?wrong_key=true

PUT /mock/authorize 
    ?error=
    ?wildcard_domain=
    ?state=

PUT /mock/oauth/token
    ?status= 
    ?error= 

PUT /mock/oauth/introspection
    ?status= 
    ?error= 

PUT /mock/oauth/userinfo
    ?status= 
    ?error= 

DELETE /mock/

PUT /mock/user/:user
    where `:user` can be `0, 1 or 2` per user array in `src/users.js`

PUT /mock/claims

```
    /mock/claims?email=mock@mock.example
```

PUT /mock/invite
    ?error

PUT /mock/set
    {
        header
        payload
    }

DELETE /mock


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
