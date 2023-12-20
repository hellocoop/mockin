// oauth.js

import MOCK from './mock.js'
import openid from './openid-configuration.js'
import { verifyChallenge } from "pkce-challenge"

import { users } from './users.js'
import { randomUUID } from 'crypto'
import { ISSUER } from './config.js'
import sign from './sign.js'
import { codes } from './authorize.js'

const oauthErrorStatusCodes = {
    "access_denied": 403,
    "invalid_client": 401,
    "invalid_grant": 400,
    "invalid_request": 400,
    "invalid_scope": 400,
    "invalid_token": 401, 
    "server_error": 500,
    "temporarily_unavailable": 503,
    "unauthorized_client": 400,
    "unsupported_grant_type": 400,
    "unsupported_response_type": 400,
};


const JWkS = (await import('./mock.jwks.json', {assert: {type: "json"}})).default

export const token = async ( req, res ) => {
    const code = req.body?.code || req.json?.code
    if (!code)
        return res.status(400).send({error:'invalid_request'})
    const request = codes[code]
    if (!request)
        return res.status(400).send({error:'invalid_grant'})
    delete codes[code] // one time use

    const client_id = req.body?.client_id || req.json?.client_id
    if (!client_id)
        return res.status(400).send({error:'invalid_request'})
    if (client_id !== request.client_id)
        return res.status(400).send({error:'invalid_request'})

    const redirect_uri = req.body?.redirect_uri || req.json?.redirect_uri
    if (!redirect_uri)
        return res.status(400).send({error:'invalid_request'})
    if (redirect_uri !== request.redirect_uri)
        return res.status(400).send({error:'invalid_request'})

    const grant_type = req.body?.grant_type || req.json?.grant_type
    if (!grant_type)
        return res.status(400).send({error:'invalid_request'})
    if (grant_type !== 'authorization_code')
        return res.status(400).send({error:'unsupported_grant_type'})

    const code_verifier = req.body?.code_verifier || req.json?.code_verifier
    if (request.code_challenge && !code_verifier)
        return res.status(400).send({error:'invalid_request'})
    if (!request.code_challenge && code_verifier)
        return res.status(400).send({error:'invalid_request'})

    const verifiedChallenge = await verifyChallenge(code_verifier, query.code_challenge)
    if (!verifiedChallenge)
        return res.status(400).send({error:'invalid_grant'})

    const { token } = MOCK
    if (token?.status || token?.error)
        return res.status(token?.status || 200).send({error:token?.error})
    if (token?.error)
        return res.status(oauthErrorStatusCodes[token.error] || 400).send({error:token.error})

    const id_payload = {
        iss: ISSUER,
        aud: request.client_id,
        nonce: request.nonce,
        jto: randomUUID(),
        iat: Math.floor(Date.now()/1000),
        ...users[0],
        ...token.payload || {}, 
    }
    const id_token = await sign(id_payload, token.options, token.wrongKey)
    if (id_token instanceof Error)
        return res.status(500).send({error:id_token.message})

    const access_payload = {
        iss: ISSUER,
        aud: ISSUER,
        iat: Math.floor(Date.now()/1000),
        ...users[0],
        ...token.payload || {}, 
    }
    const access_token = await sign(access_payload, token.options, token.wrongKey)
    if (access_token instanceof Error)
        return res.status(500).send({error:access_token.message})

    res.header('Content-Type', 'application/json')
    res.send({
        token_type: 'Bearer',
        id_token,
        access_token,
    })
    return res
}

export const introspect = async ( req, res ) => {
    // TODO check valid call

}

export const userinfo = async ( req, res ) => {
    // TODO check valid call

}

export const wellknown = async ( req, res ) => {
    res.header('Content-Type', 'application/json')
    res.send(openid)
}

export const jwks = async ( req, res ) => {
    res.header('Content-Type', 'application/json')
    res.send(JWkS)

}