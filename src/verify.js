// verify Hello issuer jwt

import { jwtVerify, createLocalJWKSet, decodeProtectedHeader, decodeJwt } from 'jose'

import { ISSUER } from './config.js'

import jwks from './mock.jwks.js'

const JWKS = createLocalJWKSet(jwks)

const verify = async function (token, audience, nonce) {
    if (!token) return({error:'token_required'})
    if (!audience) return({error:'client_id_required'})
    try {
        const header = decodeProtectedHeader(token)
        const payload = decodeJwt(token)
        if (!header?.alg || !payload?.iss)
            return({active:false})
        if (payload?.nonce && !nonce)
            return({error:'nonce_required'})
        if (header.alg != 'RS256') {
            console.error('Invalid algorithm: expected RS256, got ', header.alg)
            return({active:false})
        }
        const typ = header?.typ?.toLowerCase()
        if (typ != 'jwt' && typ != 'command+jwt') {
            console.error('Invalid type: expected JWT or command+jwt, got ', header.typ)
            return({active:false})
        }
        if (payload.iss != ISSUER) {
            console.error('Invalid issuer: expected ', ISSUER, ' got ', payload.iss)
            return({active:false})
        }
        if (payload.aud != audience) {
            console.error('Invalid audience: expected ', audience, ' got ', payload.aud)
            return({active:false})
        }
        if (payload.nonce && payload.nonce != nonce) {
            console.error('Invalid nonce: expected ', nonce, ' got ', payload.nonce)
            return({active:false})
        }
        const { payload: decoded } = await jwtVerify(token, JWKS, {
            algorithms: ['RS256'],
            issuer: ISSUER,
            audience,
        })
        // all good if we made it here
        const result = {...decoded, active: true}
        return result
    } catch (err) {
        console.error(err)
        return (err instanceof Error) ? err : (new Error(err))
    }
}

export default verify
