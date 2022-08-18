# mock server

Mock Hellō server for development coming soon!

## Endpoints

### /authorize

authorization point for both OAuth and OIDC flows

### /oauth/token

returns ID token and access token if OIDC flow, access token if OAuth flow

### /oauth/introspection

verifies ID Token and returns payload

### /oauth/userinfo

returns same payload as the ID Token

### /.well-known/openid-configuration

Returns an openid-configuation JSON file
All URLs use hostname that server is running on

### jwks endpoint

A jwks endpoint per the OIDC configuration file that returns the jwks file
