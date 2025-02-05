// authorize.js

import { randomUUID } from 'crypto'
import { VALID_RESPONSE_MODE, VALID_RESPONSE_TYPE } from '@hellocoop/constants'
import { ISSUER } from './config.js'
import sign from './sign.js'
import defaultUser, { loginHints, domainHints } from './users.js'
import mock from './mock.js'

export const codes = {}

let releases = {}

const validResponseTypes = new Set(VALID_RESPONSE_TYPE)

const validResponseModes = new Set(VALID_RESPONSE_MODE)

const UPDATE_SUPPORTED_SCOPE_SET = new Set(['picture','email','phone','ethereum','banner', 'discord', 'twitter', 'github', 'gitlab'])


// user[0] claims define the valid scopes
// TBD Support for 'profile' scope
// TBD Remove 'profile_update' scope
const validScopes = new Set([...['openid','profile_update'],...Object.keys(defaultUser)])
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
            code_challenge_method,
            login_hint,
            domain_hint,
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
    let _scopes = scope.split(' ')
    let scopesSet = new Set(_scopes)
    if (_scopes.length !== scopesSet.size)
        return sendInvalidRequest('duplicate scopes')
    const invalidScopes = _scopes.filter(scope => !validScopes.has(scope))
    if (invalidScopes.length)
        return sendInvalidRequest(`invalid scopes: ${invalidScopes.join(', ')}`)
    if (!scopesSet.has('openid'))
        return sendInvalidRequest('missing openid scope')
    if (response_type === 'id_token' && code_challenge)
        return sendInvalidRequest('code_challenge is invalid for id_token response_type')
    if (code_challenge_method && code_challenge_method != 'S256')
        return sendInvalidRequest('only code_challenge_method=S256 is supported')

    let MOCK, userClaims;
    if (login_hint) {
        const user = loginHints[login_hint]
        if (!user) {
            console.error('mock user does not exist for login_hint', login_hint)
            return sendInvalidRequest('non-existent user for login_hint')
        }
        MOCK = user
        userClaims = {...user, ...MOCK.claims || {}}
    } else if (domain_hint) { // if both are passed, login_hint takes precedence
        const user = domainHints[domain_hint]
        if (!user) {
            console.error('mock user does not exist for domain_hint', domain_hint)
            return sendInvalidRequest('non-existent user for domain_hint',)
        }
        MOCK = user
        userClaims = {...user, ...MOCK.claims || {}}
    } else { // get current user in case profile_update scope
        MOCK = mock()
        userClaims = {...defaultUser, ...MOCK.claims || {}}
    }

    const claims = {}
    claims.sub = userClaims.sub

    // we got a valid request -- check if we are to mock an error
    if (MOCK.authorize?.error) 
        return sendResponse(res, response_mode, redirect_uri, {...params, error:MOCK.authorize.error})

    // all good -- let's mint a mocked id_token
    // first lets get the previous claims for this user if any scope superset
    const previousClaims = releases[claims.sub] || {}
    Object.keys(previousClaims).forEach(scope => scopesSet.add(scope))

    userClaims = {...userClaims, ...previousClaims || {}, ...MOCK.claims || {}}

    scopesSet.forEach(scope => { 
        if (scope !== 'openid') claims[scope] = userClaims[scope]
    })
    if (scopesSet.has('email')) {
        claims.email_verified = true
    }
    if (scopesSet.has('phone')) {
        claims.phone_verified = true
    }
    releases[claims.sub] = claims // for next time
    let iat = Math.floor(Date.now()/1000)
    if (MOCK?.token?.expired) {
        iat -= 60 * 60 // 1 hour
    }
    const id_payload = {
        iss: MOCK?.token?.iss || ISSUER,
        aud: MOCK?.token?.aud || client_id,
        jti: randomUUID(),
        iat,
        nonce,
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
        ...id_payload,
        aud: MOCK?.token?.aud || ISSUER,
    }
    delete access_payload.nonce

    const access_token = await sign(access_payload, MOCK?.token?.options, MOCK?.token?.wrongKey)
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

export const clearState = () => {
    releases = {}
}

export default authorize