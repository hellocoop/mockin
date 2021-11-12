# Mock Interchange

# NOTES DURING DEVELOPMENT

Deployed at `https:\\mock.hello.coop\`

- Let's make this a separate GitHub repo so developers can clone and run their own mock server
- have a JSON file that is read in for how to build the mock tokens
- have a default mock that is served


This is a mock service running at https"://mock.hello.dev

The mock service will only work against `dev_` application IDs to prevent production deployments from inadvertently running against it

All inputs in the authorization request will be checked as they are at https://consent.hello.coop, and the same errors returned if there is an error in the request.

The mock will look for a `mock` parameter, or a `login_hint` parameter that will select what the mock service will return. If no parameter, it will provide `default`


`john_doe@example.com` will return the following JSON (subject to requested scopes)

        {
            "given_name": "John",
            "family_name": "Doe",
            "nickname": "Jack",
            "name": "John Doe Sr",
            "email": "john.doe@example.com,
            "email_verified": true,
            "phone_number": "+15555550123",
            "phone_number_verified": true
        }


`john_really_long_name_doe@example.com` will return the following JSON (subject to requested scopes)

`john_doe_long_email@example.com` will return the following JSON (subject to requested scopes)

`john_doe_uk_phone@example.com` will return the following JSON (subject to requested scopes)

Other examples
- non-english names
- reversed name order names


`john_doe_expired@example.com` will return John Doe, but the token will be back dated so that it is expired

`john_doe_invalid_sig@example.com` will return Joe Doe, but with an invalid signature

Other possible errors:

- wrong aud
- wrong iss
- wrong nonce
- Q: JST header issues?
- invalid JWT format
- invalid JSON in header
- invalid JSON in payload
- 503 error

`user_cancel@example.com` will return a user cancel error XXXX

# Cypress Plugin

Have a `cy.hello()` function. Default, user, nonce, etc. 

# Provider Mock

Metadata file for each provider and routing code for each one to mock each login provider

`apple.mock.hello.dev` would be issuer

