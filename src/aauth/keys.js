// aauth/keys.js — Ed25519 key generation for AAuth token signing

import { generateKeyPair, exportJWK } from 'jose'

const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' })

const kid = `aauth-${new Date().toISOString().replace(/[:.]/g, '-')}`

const publicJwk = await exportJWK(publicKey)
publicJwk.kid = kid
publicJwk.use = 'sig'
publicJwk.alg = 'EdDSA'
publicJwk.key_ops = ['verify']

const privateJwk = await exportJWK(privateKey)
privateJwk.kid = kid
privateJwk.alg = 'EdDSA'

export { publicJwk, privateJwk, privateKey, kid }
