// sign jwts
import { SignJWT, importJWK } from 'jose'

import jwk from './mock.private.jwk.js'
const privateKey = await importJWK(jwk.private, 'RS256')

import jwkWrong from './wrong.private.jwk.js'
const privateKeyWrong = await importJWK(jwkWrong.private, 'RS256')


const sign = async function (payload, newOptions, wrong) {
    if (!jwk)
        return new Error('no key found')
    const headerOverrides = newOptions?.header || {}
    const header = {
        alg: 'RS256',
        kid: jwk.private.kid,
        typ: 'JWT',
        ...headerOverrides,
    }
    const builder = new SignJWT({...payload})
        .setProtectedHeader(header)
    if (!payload.iat)
        builder.setIssuedAt()
    if (!payload.exp) {
        if (payload.iat) {
            // calculate exp relative to iat to match jsonwebtoken behavior
            builder.setExpirationTime(payload.iat + 5 * 60)
        } else {
            builder.setExpirationTime(newOptions?.expiresIn || '5m')
        }
    }
    const token = await builder.sign(wrong ? privateKeyWrong : privateKey)
    return token
}

export default sign
