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


export const introspect = async function ( req, reply ) {
    const token = req.body?.token || req.body?.id_token
    const client_id = req.body?.client_id || req.body?.audience
    if (!token) return reply.status(400).send({error:'invalid_request',error_description:'"token" is required'})
    if (!client_id) return reply.status(400).send({error:'invalid_request',error_description:'"client_id" is required'})
    const {introspect} = MOCK
    if (introspect?.status || introspect?.error)
        return reply.status(introspect?.status || 200).send({error:introspect?.error})
    const payload = await verify( token, client_id, req.body?.nonce )
    if (payload instanceof Error) {
        reply.log.error(payload)
        return reply.send({active:false})
    }
    return reply.send(payload)
}

export const userinfo = async function ( req, reply ) {
    reply.headers({
        'Cache-Control':	            'no-store',
        'Pragma':	                    'no-cache',
        'Access-Control-Allow-Origin':  req.headers.origin,
        'Access-Control-Allow-Methods': 'GET, POST',          
    }) // both POST and GET methods are allowed


    if (!req.headers.authorization || req.headers.authorization.indexOf('Bearer ') === -1)
        return reply.code(400).send({error:'invalid_request',error_description:'no access token found'})
    const token = req.headers.authorization.split(' ')[1]

    const payload = await verify(token,'consent')

    if (payload instanceof Error) {
        return reply.code(401).send({error:'invalid_token',error_description:payload.message})
    }
    const userinfo = {
        iss: payload.iss,
        sub: payload.sub,
        aud: payload.aud
    }
    for (const scope of payload.scope) {
        userinfo[scope] = payload[scope]
    }
    return reply.send(userinfo)
}


export const wellknown = async ( req, res ) => {
    res.header('Content-Type', 'application/json')
    res.send(openid)
}

export const jwks = async ( req, res ) => {
    res.header('Content-Type', 'application/json')
    res.send(JWkS)

}