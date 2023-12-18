import { ISSUER } from './config'

export default () => { return(`{
    "authorization_endpoint": "${ISSUER}/authorize",
    "issuer": "${ISSUER}",
    "jwks_uri": "${ISSUER}/jwks",
    "introspection_endpoint": "${ISSUER}/oauth/introspect",
    "token_endpoint": "${ISSUER}/oauth/token",
    "userinfo_endpoint": "${ISSUER}/oauth/userinfo",
    "response_modes_supported": [
        "query",
        "fragment",
        "form_post"
    ],
    "subject_types_supported": [
        "pairwise"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic"
    ],
    "introspection_endpoint_auth_methods_supported": [
        "none"
    ],
    "code_challenge_methods_supported": [
        "S256"
    ],
    "grant_types_supported": [
        "authorization_code",
        "implicit"
    ],
    "response_types_supported": [
        "id_token",
        "code"
    ],
    "scopes_supported": [
        "openid",
        "name",
        "nickname",
        "family_name",
        "given_name",
        "picture",
        "email",
        "phone",
        "ethereum",
        "profile_update"
    ],
    "claims_supported": [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "jti",
        "nonce",
        "name",
        "picture",
        "email",
        "email_verified",
        "phone",
        "phone_verified",
        "ethereum"
    ]
}`)}