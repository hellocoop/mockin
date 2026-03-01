// aauth/metadata.js — /.well-known/aauth-issuer.json handler

import { ISSUER } from '../config.js'

export const metadata = async (req, res) => {
    res.header('Content-Type', 'application/json')
    res.send({
        issuer: ISSUER,
        token_endpoint: `${ISSUER}/aauth/token`,
        interaction_endpoint: `${ISSUER}/aauth/interaction`,
        jwks_uri: `${ISSUER}/aauth/jwks`,
    })
}
