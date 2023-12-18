// verify Hello issuer jwt

import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'

import { ISSUER } from './config.js'

const jwks = (await import('./mock.jwks.json', {assert: {type: "json"}})).default

const pems = {}
jwks.keys.forEach( jwk => {
    pems[jwk.kid] = jwkToPem(jwk)
})

verify = async function (token, audience, nonce) {
    if (!token) return({error:'token_required'})
    if (!audience) return({error:'client_id_required'})
    const options = {
        algorithms: ['RS256'],
        issuer: ISSUER,
        audience: audience,
        nonce: nonce
    }
    try {
        const {header,payload} = jwt.decode(token,{complete:true})
        if (!header?.alg || !payload?.iss)
            return({active:false})
        if (payload?.nonce && !nonce)
            return({error:'nonce_required'})
        const key = pems[header?.kid]
        if (    (header.alg != 'RS256')
            ||  (header.typ != 'JWT')
            ||  (payload.iss != ISSUER)
            ||  (payload.aud != audience)
            ||  (payload.nonce && payload.nonce != nonce)
            ||  (!key) )
            return({active:false})
        const decoded = jwt.verify(token, key, options)
        // all good if we made it here
        decoded.active = true
        return decoded
    } catch (err) {
        console.error(err)
        return (err instanceof Error) ? err : (new Error(err))
    }
}

export default verify