// aauth/pending.js — GET /aauth/pending/:id polling endpoint

import { randomUUID } from 'crypto'
import { SignJWT } from 'jose'

import { ISSUER } from '../config.js'
import { privateKey, kid } from './keys.js'
import { getConfig } from './mock.js'
import defaultUser from '../users.js'
import { getPendingById } from './state.js'

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

export const pending = async (req, res) => {
    const { id } = req.params
    const pendingReq = getPendingById(id)

    if (!pendingReq) {
        return res.code(404).send({ error: 'not_found' })
    }

    if (pendingReq.status === 'pending') {
        const location = `${ISSUER}/aauth/pending/${id}`
        res.code(202)
        res.header('Location', location)
        res.header('Retry-After', '5')
        res.header('Cache-Control', 'no-store')
        return res.send({
            status: 'pending',
            location,
        })
    }

    if (pendingReq.status === 'error') {
        const error = pendingReq.error || 'denied'
        const statusCode = error === 'expired' ? 408 : error === 'invalid_code' ? 410 : 403
        return res.code(statusCode).send({ error })
    }

    if (pendingReq.status === 'approved') {
        const config = getConfig()
        const { token, lifetime } = await issueAuthToken({
            agent_id: pendingReq.agent_id,
            agent_jwk: pendingReq.agent_jwk,
            resource: pendingReq.resource,
            scope: pendingReq.scope,
            user_sub: pendingReq.user_sub || defaultUser.sub,
            claims: config.claims,
        })
        return res.send({
            auth_token: token,
            expires_in: lifetime,
        })
    }
}
