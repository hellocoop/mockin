// aauth/token.js — /aauth/token handler

import { randomUUID } from 'crypto'
import { SignJWT } from 'jose'

import { ISSUER } from '../config.js'
import { privateKey, kid } from './keys.js'
import { getConfig } from './mock.js'
import defaultUser from '../users.js'
import {
    createPendingRequest,
    getPendingByRequestTicket,
    updatePendingRequest,
} from './state.js'

async function issueAuthToken({ agent_id, agent_jwk, resource, scope, user_sub, claims }) {
    const config = getConfig()
    const lifetime = config.token_lifetime || 3600
    const user = { sub: user_sub, ...defaultUser }
    const tokenClaims = {
        iss: ISSUER,
        sub: user_sub,
        agent: agent_id,
        cnf: { jwk: agent_jwk },
        scope: scope || 'openid',
    }
    if (resource) tokenClaims.aud = resource
    if (claims) Object.assign(tokenClaims, claims)

    const token = await new SignJWT(tokenClaims)
        .setProtectedHeader({ alg: 'EdDSA', typ: 'auth+jwt', kid })
        .setIssuedAt()
        .setExpirationTime(`${lifetime}s`)
        .setJti(randomUUID())
        .sign(privateKey)

    const refreshToken = randomUUID()

    return {
        access_token: token,
        token_type: 'auth+jwt',
        expires_in: lifetime,
        refresh_token: refreshToken,
        scope: tokenClaims.scope,
    }
}

function extractAgentIdentity(aauth) {
    let agent_id = null
    let agent_jwk = aauth.publicKey

    if (aauth.keyType === 'jwt' && aauth.jwt) {
        agent_id = aauth.jwt.payload.iss || null
    }
    if (!agent_id) {
        agent_id = aauth.thumbprint
    }

    return { agent_id, agent_jwk }
}

export const token = async (req, res) => {
    const config = getConfig()

    // Return error immediately only if not in interaction mode
    if (config.error && !config.interaction_required) {
        return res.code(400).send({
            error: config.error,
            error_description: `Mock error: ${config.error}`,
        })
    }

    const body = req.body || {}
    const { agent_id, agent_jwk } = extractAgentIdentity(req.aauth)

    // Polling with request_ticket
    if (body.request_ticket) {
        const pending = getPendingByRequestTicket(body.request_ticket)
        if (!pending) {
            return res.code(400).send({ error: 'invalid_request', error_description: 'Unknown request_ticket' })
        }
        if (pending.status === 'pending') {
            return res.send({ status: 'pending' })
        }
        if (pending.status === 'denied') {
            return res.code(403).send({ error: 'access_denied' })
        }
        if (pending.status === 'approved') {
            const tokenResponse = await issueAuthToken({
                agent_id: pending.agent_id,
                agent_jwk: pending.agent_jwk,
                resource: pending.resource,
                scope: pending.scope,
                user_sub: pending.user_sub || defaultUser.sub,
                claims: config.claims,
            })
            return res.send(tokenResponse)
        }
    }

    // Refresh token
    if (body.refresh_token) {
        const tokenResponse = await issueAuthToken({
            agent_id,
            agent_jwk,
            resource: body.resource,
            scope: body.scope,
            user_sub: defaultUser.sub,
            claims: config.claims,
        })
        return res.send(tokenResponse)
    }

    // Initial authorization request
    if (config.auto_grant && !config.interaction_required) {
        const tokenResponse = await issueAuthToken({
            agent_id,
            agent_jwk,
            resource: body.resource,
            scope: body.scope,
            user_sub: defaultUser.sub,
            claims: config.claims,
        })
        return res.send(tokenResponse)
    }

    // Interaction required — generate tickets
    const request_ticket = randomUUID()
    const interaction_ticket = randomUUID()
    const callback_ticket = body.callback_ticket || randomUUID()

    createPendingRequest(request_ticket, {
        interaction_ticket,
        agent_id,
        agent_jwk,
        resource: body.resource,
        scope: body.scope,
        purpose: body.purpose,
        callback_url: body.callback_url,
        callback_ticket,
        user_sub: null,
    })

    return res.send({
        request_ticket,
        interaction_ticket,
        interaction_endpoint: `${ISSUER}/aauth/interaction`,
    })
}
