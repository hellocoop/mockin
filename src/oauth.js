// oauth.js
import { verifyChallenge } from "pkce-challenge"
import { VALID_IDENTITY_CLAIMS } from '@hellocoop/constants'

import mock from './mock.js'
import openid from './openid-configuration.js'
import { ISSUER } from './config.js'
import verify from './verify.js'
import { codes } from './authorize.js'

import JWkS from './mock.jwks.js'

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



export const token = async ( req, res ) => {
    const MOCK = mock()
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

    const { token } = MOCK
    if (token?.status && token?.error)
        return res.status(token?.status).send({error:token?.error})
    if (token?.error)
        return res.status(oauthErrorStatusCodes[token.error] || 400).send({error:token.error})

    if (request.code_challenge) {
        const verifiedChallenge = await verifyChallenge(code_verifier, request.code_challenge)
        if (!verifiedChallenge)
            return res.status(400).send({error:'invalid_grant'})    
    } else { // check we got a credential
        let client_secret = null
        if (req.headers.authorization && req.headers.authorization.indexOf('Basic ') >= 0) {
            const base64Credentials =  req.headers.authorization.split(' ')[1]
            const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii')
            const [c_id, c_secret] = credentials.split(':')
            if (c_secret)
                client_secret = c_secret
        }
        if (!client_secret)
            client_secret = req.body?.client_secret
        if (!client_secret)
            return res.status(400).send({error:'invalid_request',error_description:"code_verifier required if unauthenticated client"})
        if (MOCK.client_secret && MOCK.client_secret !== client_secret)
            return res.status(401).send({error:'invalid_client',error_description:"invalid client_secret"})
    }

    res.header('Content-Type', 'application/json')
    res.send({
        token_type: 'Bearer',
        id_token: request.id_token,
        access_token: request.access_token,
    })
    return res
}


export const introspect = async function ( req, reply ) {
    const token = req.body?.token || req.body?.id_token
    const client_id = req.body?.client_id || req.body?.audience
    if (!token) return reply.status(400).send({error:'invalid_request',error_description:'"token" is required'})
    if (!client_id) return reply.status(400).send({error:'invalid_request',error_description:'"client_id" is required'})
    const {introspect} = mock()
    if (introspect?.status || introspect?.error)
        return reply.status(introspect?.status || 200).send({error:introspect?.error})
    if (introspect?.active === false)
        return reply.status(200).send({active:false})
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


    if (!req.headers.authorization)
        return reply.code(400).send({error:'invalid_request',error_description:'no authorization header found'})
    if (req.headers.authorization.indexOf('Bearer ') === -1)
        return reply.code(400).send({error:'invalid_request',error_description:'"Bearer" found'})
    const token = req.headers.authorization.split(' ')[1]
    if (!token) 
        return reply.code(400).send({error:'invalid_request',error_description:'no access token found'})

    const payload = await verify(token,ISSUER)

    if (payload instanceof Error) {
        return reply.code(401).send({error:'invalid_token',error_description:payload.message})
    }
    const userinfo = {
        iss: payload.iss,
        sub: payload.sub,
    }
    VALID_IDENTITY_CLAIMS.forEach(claim => {
        if (payload[claim]) userinfo[claim] = payload[claim]
    })
    // Hellō extensions for managed accounts
    const extensionClaims = ['tenant_sub', 'tenant', 'role', 'idp']
    extensionClaims.forEach(claim => {
        if (payload[claim]) userinfo[claim] = payload[claim]
    })
    return reply.send(userinfo)
}


export const wellknown = async ( req, res ) => {
    res.header('Content-Type', 'application/json')
    res.send(openid())
}

export const jwks = async ( req, res ) => {
    res.header('Content-Type', 'application/json')
    res.send(JWkS)

}