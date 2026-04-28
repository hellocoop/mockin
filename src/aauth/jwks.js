// aauth/jwks.js — GET /.well-known/jwks.json (PS public keys)

import { publicJwk } from './keys.js'

export const jwks = async (req, res) => {
    res.header('Content-Type', 'application/json')
    res.header('Cache-Control', 'public, max-age=3600')
    return res.send({ keys: [publicJwk] })
}
