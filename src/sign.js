// sign jwts
import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'

const jwk = (await import('./mock.private.jwk.json', {assert: {type: "json"}})).default
const pem = jwkToPem(jwk.private,{private:true})  

const jwkWrong = (await import('./mock.private.jwk.json', {assert: {type: "json"}})).default
const pemWrong = jwkToPem(jwk.private,{private:true})  


const sign = async function (payload, newOptions, wrong) {
    if (!jwk)
        return new Error('no key found')
    const options = {
        keyid:      jwk.private.kid,
        algorithm: 'RS256',
        ...newOptions || {}
    }
    if (!payload.exp && !options.expiresIn)
        options.expiresIn = '5m'
    const token = jwt.sign( payload, wrong ? pemWrong : pem, options)  
    return token
}

export default sign

