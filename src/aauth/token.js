// aauth/token.js — /aauth/token handler

import { randomUUID } from 'crypto'
import { SignJWT } from 'jose'

import { ISSUER } from '../config.js'
import { privateKey, kid } from './keys.js'
import { getConfig } from './mock.js'
import defaultUser from '../users.js'
import { createPendingRequest, updatePendingRequest } from './state.js'

async function issueAuthToken({ agent_id, agent_jwk, resource, scope, user_sub, claims }) {
    const config = getConfig()
    const lifetime = config.token_lifetime || 3600
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

    return { token, lifetime }
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

    // Refresh — agent presents expired auth_token
    if (body.auth_token) {
        const { token, lifetime } = await issueAuthToken({
            agent_id,
            agent_jwk,
            resource: body.resource,
            scope: body.scope,
            user_sub: defaultUser.sub,
            claims: config.claims,
        })
        return res.send({
            auth_token: token,
            expires_in: lifetime,
        })
    }

    // Direct grant (auto_grant and no interaction required)
    if (config.auto_grant && !config.interaction_required) {
        const { token, lifetime } = await issueAuthToken({
            agent_id,
            agent_jwk,
            resource: body.resource,
            scope: body.scope,
            user_sub: defaultUser.sub,
            claims: config.claims,
        })
        return res.send({
            auth_token: token,
            expires_in: lifetime,
        })
    }

    // Deferred response — create pending request
    const { id: pendingId, code } = createPendingRequest({
        agent_id,
        agent_jwk,
        resource: body.resource,
        scope: body.scope,
        purpose: body.purpose,
        user_sub: null,
    })

    const location = `${ISSUER}/aauth/pending/${pendingId}`
    const requireMode = config.require || 'interaction'

    // Approval mode — auto-resolve immediately (no user interaction needed)
    if (requireMode === 'approval') {
        if (config.error) {
            updatePendingRequest(pendingId, { status: 'error', error: config.error })
        } else {
            updatePendingRequest(pendingId, { status: 'approved', user_sub: defaultUser.sub })
        }
        res.code(202)
        res.header('Location', location)
        res.header('Retry-After', '0')
        res.header('Cache-Control', 'no-store')
        return res.send({
            status: 'pending',
            location,
            require: 'approval',
        })
    }

    // Interaction mode (default) — agent must direct user to interaction endpoint
    res.code(202)
    res.header('Location', location)
    res.header('Retry-After', '0')
    res.header('Cache-Control', 'no-store')
    res.header('AAuth', `require=interaction; code="${code}"`)
    return res.send({
        status: 'pending',
        location,
        require: 'interaction',
        code,
    })
}
