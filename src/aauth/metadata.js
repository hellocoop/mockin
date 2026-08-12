// aauth/metadata.js — GET /.well-known/aauth-person.json
//
// Person Server metadata. Per draft-hardt-aauth-protocol §Person Server
// Metadata the PS publishes its endpoints here so agents can discover them.
//
// -11 renamed `token_endpoint` to `auth_token_endpoint` and made
// `person_token_endpoint` REQUIRED of every PS. Both are published here;
// @aauth/bootstrap 2.0.0 hard-fails against a PS missing either.

import { ISSUER } from '../config.js'

export const metadata = async (req, res) => {
    res.header('Content-Type', 'application/json')
    res.header('Cache-Control', 'public, max-age=3600')
    return res.send({
        issuer: ISSUER,
        name: 'Mockin Person Server',
        description: '**Mockin** — a mock Person Server for AAuth testing.',
        jwks_uri: `${ISSUER}/aauth/jwks.json`,
        // Both token endpoints sit under a shared /aauth/token prefix, as
        // Wallet does. The bare prefix is not a route.
        auth_token_endpoint: `${ISSUER}/aauth/token/auth`,
        person_token_endpoint: `${ISSUER}/aauth/token/person`,
        permission_endpoint: `${ISSUER}/aauth/permission`,
        audit_endpoint: `${ISSUER}/aauth/audit`,
        interaction_endpoint: `${ISSUER}/aauth/interaction`,
        bootstrap_endpoint: `${ISSUER}/aauth/bootstrap`,
    })
}
