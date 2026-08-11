// aauth/verify-agent-token.js — verify an aa-agent+jwt.
//
// Shared by the request preHandler (the agent token presented in
// Signature-Key) and by the person/auth token endpoints when a
// `subagent_token` is presented in the request body.
//
//   1. typ is aa-agent+jwt and alg is acceptable (§Signature Algorithms)
//   2. iss present; the issuer's JWKS is discovered via {iss}/.well-known/{dwk}
//   3. the JWT signature verifies against that JWKS
//   4. sub and cnf.jwk are present

import * as jose from 'jose'

import { getEntity, AGENT_DWK } from './entity-cache.js'
import { ACCEPTED_JWT_ALGS, checkJwtAlg } from './algorithms.js'

/**
 * @param {string} raw            the compact JWT
 * @param {object} [decoded]      { header, payload } when the caller already has them
 * @returns {Promise<{payload?: object, header?: object, error?: string}>}
 */
export async function verifyAgentToken(raw, decoded) {
    let header = decoded?.header
    let payload = decoded?.payload
    if (!header || !payload) {
        try {
            header = jose.decodeProtectedHeader(raw)
            payload = jose.decodeJwt(raw)
        } catch {
            return { error: 'malformed agent_token' }
        }
    }

    if (header.typ !== 'aa-agent+jwt') {
        return { error: `expected aa-agent+jwt, got ${header.typ}` }
    }
    const algError = checkJwtAlg(header.alg)
    if (algError) return { error: `agent_token ${algError}` }

    if (!payload.iss) return { error: 'agent_token missing iss' }

    let entity
    try {
        entity = await getEntity(payload.iss, payload.dwk || AGENT_DWK)
    } catch (err) {
        return { error: `agent server discovery failed: ${err.message}` }
    }

    try {
        await jose.jwtVerify(raw, jose.createLocalJWKSet(entity.jwks), {
            algorithms: ACCEPTED_JWT_ALGS,
        })
    } catch (err) {
        return { error: `agent_token signature: ${err.message}` }
    }

    if (!payload.sub) return { error: 'agent_token missing sub' }
    if (!payload.cnf?.jwk) return { error: 'agent_token missing cnf.jwk' }

    return { header, payload, metadata: entity.metadata }
}
