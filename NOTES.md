# Mock Interchange

A docker image that can be used by any Hellō Developer
Deployed at https://mock.hello.dev and accessible from https://playground.hello.dev


# Endpoints

`/` - consent server, takes OIDC parameters and returns processed result
`/oauth/token`
`/oauth/userinfo`
`/.well-known/openid-configuration`
`/.well-known/jwks`

# Environment Variables

`ISSUER`
`CLIENT_ID`
`REDIRECT_URI`

# Fixtures

response = query.login_hint || query.mock || DEFAULT

`some_name.json` for each fixture

`DEFAULT.json` 

`error_type.json` for different error responses


# jkws

- generate new key pair on boot
- have static key that is used for wrong signing key error


# Other examples
- non-english names

# Other possible errors:

- wrong aud
- wrong iss
- wrong nonce
- Q: JST header issues?
- invalid JWT format
- invalid JSON in header
- invalid JSON in payload
- 503 error

# Cypress Plugin

Have a `cy.hello()` function. Default, user, nonce, etc. 


