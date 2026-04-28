// aauth/metadata.js — GET /.well-known/aauth-person.json
//
// Person Server metadata. Per draft-hardt-aauth-protocol §Metadata Documents
// the PS publishes its endpoints here so agents can discover them.

import { ISSUER } from '../config.js'

export const metadata = async (req, res) => {
    res.header('Content-Type', 'application/json')
    res.header('Cache-Control', 'public, max-age=3600')
    return res.send({
        issuer: ISSUER,
        jwks_uri: `${ISSUER}/aauth/jwks.json`,
        token_endpoint: `${ISSUER}/aauth/token`,
        permission_endpoint: `${ISSUER}/aauth/permission`,
        audit_endpoint: `${ISSUER}/aauth/audit`,
        interaction_endpoint: `${ISSUER}/aauth/interaction`,
        bootstrap_endpoint: `${ISSUER}/aauth/bootstrap`,
    })
}
