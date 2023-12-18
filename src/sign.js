// sign jwts
import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'

const jwk = (await import('./mock.private.jwk.json', {assert: {type: "json"}})).default
jwk.pem = jwkToPem(jwk.private,{private:true})    

const sign = async function (payload) {
    if (!jwk)
        return new Error('no key found')
    const options = {
        keyid:      jwk.private.kid,
        algorithm: 'RS256',
    }
    if (!payload.exp)
        options.expiresIn = '5m'
    const token = jwt.sign( payload, jwk.pem, options)  
    return token
}

export default sign

