// aauth/verify-resource-token.js — verify a resource_token JWT.
//
// The agent obtains the resource_token from the resource server (via
// AAuth-Requirement: requirement=auth-token) and presents it to the PS
// in the /aauth/token request body. The PS verifies that:
//
//   - typ === aa-resource+jwt
//   - JWT signature verifies against the resource server's JWKS
//   - aud matches the PS issuer
//   - agent / agent_jkt match the agent identity from HTTPSig
//   - r3_uri and r3_s256 either both present or both absent
//
// Returns the resource server URL, scope, R3 claims (if any), or an error.

import * as jose from 'jose'
import { ISSUER } from '../config.js'
import { getEntity, RESOURCE_DWK } from './entity-cache.js'

export async function verifyResourceToken(
    resourceTokenStr,
    expectedAgentId,
    expectedJkt,
) {
    let header, payload
    try {
        header = jose.decodeProtectedHeader(resourceTokenStr)
        payload = jose.decodeJwt(resourceTokenStr)
    } catch {
        return { error: 'malformed resource_token' }
    }

    if (header.typ !== 'aa-resource+jwt') {
        return {
            error: `invalid resource_token typ: expected aa-resource+jwt, got ${header.typ}`,
        }
    }
    const dwk = payload.dwk || RESOURCE_DWK
    const resourceUrl = payload.iss
    if (!resourceUrl) return { error: 'resource_token missing iss' }

    let entity
    try {
        entity = await getEntity(resourceUrl, dwk)
    } catch (err) {
        return { error: `resource discovery failed: ${err.message}` }
    }

    try {
        await jose.jwtVerify(
            resourceTokenStr,
            jose.createLocalJWKSet(entity.jwks),
        )
    } catch (err) {
        return { error: `resource_token signature: ${err.message}` }
    }

    if (payload.aud && payload.aud !== ISSUER) {
        return {
            error: `resource_token aud mismatch: expected ${ISSUER}, got ${payload.aud}`,
        }
    }
    if (payload.agent && payload.agent !== expectedAgentId) {
        return {
            error: `resource_token agent mismatch: expected ${expectedAgentId}, got ${payload.agent}`,
        }
    }
    if (payload.agent_jkt && payload.agent_jkt !== expectedJkt) {
        return {
            error: `resource_token agent_jkt mismatch: expected ${expectedJkt}, got ${payload.agent_jkt}`,
        }
    }

    const r3Uri = typeof payload.r3_uri === 'string' && payload.r3_uri ? payload.r3_uri : null
    const r3S256 = typeof payload.r3_s256 === 'string' && payload.r3_s256 ? payload.r3_s256 : null
    if (Boolean(r3Uri) !== Boolean(r3S256)) {
        return {
            error: 'resource_token must include both r3_uri and r3_s256 or neither',
        }
    }

    return {
        resource_url: resourceUrl,
        resource_metadata: entity.metadata,
        scope: typeof payload.scope === 'string' ? payload.scope : '',
        r3: r3Uri ? { uri: r3Uri, s256: r3S256 } : null,
    }
}
