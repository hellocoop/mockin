// aauth/verify-resource-token.js — verify a resource_token JWT.
//
// The agent obtains the resource_token from the resource server (via
// AAuth-Requirement: requirement=auth-token) and presents it to the PS
// in the /aauth/token request body. -11 §Resource Token Verification:
//
//   1. typ === aa-resource+jwt (and a fully-specified alg)
//   2. dwk === aauth-resource.json; signature verifies against the
//      resource's JWKS discovered at {iss}/.well-known/{dwk}
//   3. exp in the future, iat not in the future
//   4. aud === this PS
//   5. agent_jkt === thumbprint of the key that signed the HTTP request
//      (or, with a subagent_token, of the sub-agent's cnf.jwk)
//   6. `presented_jti`, `ps` and `sub` are present — the claims the resource
//      copied out of the token the request carried. Verifying them against
//      the `presented_token` the agent sent is verify-presented-token.js
//      (issue #152); the handler runs it after this function returns.
//   7. mission active — mockin has no mission store, see the note below
//
// Resource tokens no longer carry an `agent` claim: `agent_jkt` binds the
// key and the PS learns the agent from the agent token that signed the
// request.

import * as jose from 'jose'
import { ISSUER } from '../config.js'
import { getEntity, RESOURCE_DWK } from './entity-cache.js'
import { ACCEPTED_JWT_ALGS, checkJwtAlg } from './algorithms.js'

export async function verifyResourceToken(
    resourceTokenStr,
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
    const algError = checkJwtAlg(header.alg)
    if (algError) return { error: `resource_token ${algError}` }

    const dwk = payload.dwk || RESOURCE_DWK
    if (dwk !== RESOURCE_DWK) {
        return { error: `resource_token dwk must be ${RESOURCE_DWK}, got ${dwk}` }
    }
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
            { algorithms: ACCEPTED_JWT_ALGS },
        )
    } catch (err) {
        // jose checks exp/iat for us; surface expiry as its own error code
        // so the endpoint can return `expired_resource_token`.
        return {
            error: `resource_token ${err.code === 'ERR_JWT_EXPIRED' ? 'expired' : `signature: ${err.message}`}`,
            expired: err.code === 'ERR_JWT_EXPIRED',
        }
    }

    if (payload.aud !== ISSUER) {
        return {
            error: `resource_token aud mismatch: expected ${ISSUER}, got ${payload.aud}`,
        }
    }
    if (!payload.agent_jkt) {
        return { error: 'resource_token missing agent_jkt' }
    }
    if (payload.agent_jkt !== expectedJkt) {
        return {
            error: `resource_token agent_jkt mismatch: expected ${expectedJkt}, got ${payload.agent_jkt}`,
        }
    }

    // ── Step 6 (presence) ─────────────────────────────────────────────
    // The claims a resource copies out of the token it verified — the
    // person token, or on a step-up the auth token. Spec issue #95 renamed
    // `person_token_jti` → `presented_jti` (same value); resources
    // dual-emit during the transition, so accept either, preferring the
    // canonical name. The values are checked against the presented token
    // in verify-presented-token.js.
    const presentedJti = payload.presented_jti ?? payload.person_token_jti
    if (!presentedJti) {
        return {
            error: 'resource_token missing presented_jti (person_token_jti)',
        }
    }
    if (!payload.ps) return { error: 'resource_token missing ps' }
    if (!payload.sub) return { error: 'resource_token missing sub' }
    // Step 7 (mission active, before its expires_at) needs a mission
    // store. mission_endpoint is unimplemented fleet-wide, so there is no
    // mission to look up; the binding above is the part the fleet tests.

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
        ps: payload.ps,
        sub: payload.sub,
        presented_jti: presentedJti,
        agent_jkt: payload.agent_jkt,
        mission_s256: payload.mission_s256 || null,
        tenant: payload.tenant || null,
        account: payload.account || null,
        interaction: payload.interaction || null,
        r3: r3Uri ? { uri: r3Uri, s256: r3S256 } : null,
    }
}
