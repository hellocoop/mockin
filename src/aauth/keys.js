// aauth/keys.js — Ed25519 key generation for AAuth token signing

import { generateKeyPair, exportJWK } from 'jose'

const { publicKey, privateKey } = await generateKeyPair('Ed25519')

const kid = `aauth-${new Date().toISOString().replace(/[:.]/g, '-')}`

// RFC 9864: alg must be fully specified — 'Ed25519', not polymorphic 'EdDSA'.
const publicJwk = await exportJWK(publicKey)
publicJwk.kid = kid
publicJwk.use = 'sig'
publicJwk.alg = 'Ed25519'
publicJwk.key_ops = ['verify']

const privateJwk = await exportJWK(privateKey)
privateJwk.kid = kid
privateJwk.alg = 'Ed25519'

export { publicJwk, privateJwk, privateKey, kid }
