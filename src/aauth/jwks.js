// aauth/jwks.js — /aauth/jwks handler (Ed25519 public key)

import { publicJwk } from './keys.js'

export const jwks = async (req, res) => {
    res.header('Content-Type', 'application/json')
    res.send({ keys: [publicJwk] })
}
