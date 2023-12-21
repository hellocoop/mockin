// authorize.js

import { randomUUID } from 'crypto'
import { ISSUER } from './config.js'
import sign from './sign.js'
import defaultUser from './users.js'
import MOCK from './mock.js'

export const codes = {}

const validResponseTypes = new Set([
    'code',
    'id_token',
])

const validResponseModes = new Set([
    'query',
    'fragment',
    'form_post',
])

// user[0] claims define the valid scopes
const validScopes = new Set([...['openid'],...Object.keys(defaultUser)])
validScopes.delete('sub')

const sendResponse = ( res, type, redirect_uri, params ) => {
    if (type === 'query') {
        // get any existing query params
        const url = new URL(redirect_uri)
        const query = url.searchParams
        // add new params
        Object.keys(params).forEach(key => query.set(key, params[key]))
        // build new url
        url.search = query.toString()
        // send redirect
        res.redirect(url.toString())
        return
    }
    if (type === 'fragment') {
        const fragment = new URLSearchParams(params)
        // build new url
        const url = new URL(redirect_uri)
        url.hash = fragment.toString()
        // send redirect
        res.redirect(url.toString())
        return
    }
    if (type === 'form_post') {
        const form = new URLSearchParams(params)
        res.send(`<html><body onload="document.forms[0].submit()"><form method="post" action="${redirect_uri}">${form}</form></body></html>`)
        return
    }
    res.status(400).send({
        error:'invalid_request',
        error_description: `unknown response_mode "${response_mode}"`,
    })
}

const authorize = async ( req, res ) => {
    const { query: { 
            response_type,
            response_mode = 'query',
            client_id,
            redirect_uri,
            scope,
            state,
            nonce,
            code_challenge,
            code_challenge_method 
        } } = req
    const params = {}
    if (state)
        params.state = state

    if (!response_mode)
        response_mode = (response_type === 'code') ? 'query' : 'fragment'
    if (!validResponseModes.has(response_mode))
        return res.status(400).send({
            error:'invalid_request',
            error_description: `unknown response_mode "${response_mode}"`,
        })
    if (!redirect_uri)
        return res.status(400).send({
            error:'invalid_request',
            error_description: `missing redirect_uri`,
        })

    const sendInvalidRequest = (error_description) => {
        sendResponse(res, response_mode, redirect_uri, {...params, error:'invalid_request', error_description})
    }
    if (!response_type)
        return sendInvalidRequest('response_type is required')
    if (!validResponseTypes.has(response_type))
        return sendInvalidRequest('unknown response_type')
    if (!client_id) 
        return sendInvalidRequest('missing client_id')
    if (!redirect_uri)
        return sendInvalidRequest('missing redirect_uri')
    if (!scope)
        return sendInvalidRequest('missing scope')
    if (!nonce)
        return sendInvalidRequest('missing nonce')
    const scopes = scope.split(' ')
    const scopesSet = new Set(scopes)
    if (scopes.length !== scopesSet.size)
        return sendInvalidRequest('duplicate scopes')
    const invalidScopes = scopes.filter(scope => !validScopes.has(scope))
    if (invalidScopes.length)
        return sendInvalidRequest(`invalid scopes: ${invalidScopes.join(', ')}`)
    if (!scopesSet.has('openid'))
        return sendInvalidRequest('missing openid scope')
    if (response_type === 'id_token' && code_challenge)
        return sendInvalidRequest('code_challenge is not allowed for id_token response_type')
    if (response_type === 'code' && !code_challenge)
        return sendInvalidRequest('code_challenge is required for code response_type')
    if (code_challenge) {
        if (!code_challenge_method)
            return sendInvalidRequest('missing code_challenge_method')
        if (code_challenge_method != 'S256')
            return sendInvalidRequest('only S256 code_challenge_method is supported')
    }

    // we got a valid request -- check if we are to mock an error
    if (MOCK.authorize?.error) 
        return sendResponse(res, response_mode, redirect_uri, {...params, error:MOCK.authorize.error})

    // all good -- let's mint a mocked id_token

    const claims = {}
    if (scopesSet.has('email')) {
        scopes.push('email_verified')
        claims.email_verified = true
    }
    if (scopesSet.has('phone')) {
        scopes.push('phone_verified')
        claims.phone_verified = true
    }
    const userClaims = {...defaultUser, ...MOCK.claims || {}}
    claims.sub = userClaims.sub
    scopes.forEach(scope => claims[scope] = userClaims[scope])
    const id_payload = {
        iss: ISSUER,
        aud: client_id,
        jti: randomUUID(),
        // iat: Math.floor(Date.now()/1000),
        // TODO - mock an expired token or future dated token?
        nonce,
        scope: scopes.join(' '),
        ...claims,
    }
    const id_token = await sign(id_payload, MOCK?.token?.options, MOCK?.token?.wrongKey)
    if (id_token instanceof Error)
        return res.status(500).send({error:id_token.message})

    if (response_type === 'id_token') {
        return sendResponse(res, response_mode, redirect_uri, {...params, id_token})
    }

    // we are sending back a code response 

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

    const code = randomUUID()
    codes[code] = { // one time use code in global memory
        client_id,
        redirect_uri,
        scope,
        code_challenge,
        id_token,
        access_token,
        createdAt: Date.now(),
    }
    params.code = code
    return sendResponse(res, response_mode, redirect_uri, params)
       
}

export default authorize