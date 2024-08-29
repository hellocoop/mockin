// /.well-known/openid-configuration
const { 
    VALID_RESPONSE_MODE,
    VALID_RESPONSE_TYPE,
    VALID_IDENTITY_CLAIMS,
    VALID_IDENTITY_SCOPES 
} = await import('@hellocoop/constants')

import { ISSUER } from './config.js'


export default () => { return(JSON.stringify({
    "authorization_endpoint": `${ISSUER}/authorize`,
    "issuer": ISSUER,
    "jwks_uri": `${ISSUER}/jwks`,
    "introspection_endpoint": `${ISSUER}/oauth/introspect`,
    "token_endpoint": `${ISSUER}/oauth/token`,
    "userinfo_endpoint": `${ISSUER}/oauth/userinfo`,
    "response_modes_supported": VALID_RESPONSE_MODE,
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
    "response_types_supported": VALID_RESPONSE_TYPE,
    "scopes_supported": VALID_IDENTITY_SCOPES,
    "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "jti",
            "nonce",
        ...VALID_IDENTITY_CLAIMS
    ]
}, null, 2))}
