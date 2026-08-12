// aauth/issue-person-token.js — sign an aa-person+jwt for the agent.
//
// Protocol -11 §Person Token Structure. A person token identifies the
// person to ONE resource and carries no authorization: no `scope`, no
// `account`, no permission. Whether identity alone is enough to serve a
// request is the resource's decision.
//
// `sub` comes from subject.js, the same derivation issue-auth-token.js
// uses, so the value in this token is byte-equal to the one the auth
// token will carry for the same `aud`. That equality is what the PS's own
// step-6 check (§Resource Token Verification) compares against.

import { randomUUID } from 'crypto'
import { SignJWT } from 'jose'

import { ISSUER } from '../config.js'
import { privateKey, kid } from './keys.js'
import { SIGNING_ALG } from './algorithms.js'
import { directedSub } from './subject.js'
import { recordPersonToken } from './person-token-store.js'

// "Person tokens MUST NOT have a lifetime exceeding 1 hour."
export const MAX_PERSON_TOKEN_TTL = 3600

/**
 * @param {object} args
 * @param {object} args.agent_public_key    cnf.jwk — the key that will sign
 *                                          requests bearing this token (the
 *                                          sub-agent's key when a
 *                                          subagent_token was presented)
 * @param {string} args.resource            becomes `aud`
 * @param {number} [args.lifetime]          requested seconds, clamped to 1 hour
 * @param {number} [args.agent_token_exp]   the presented agent token's `exp`;
 *                                          the person token never outlives it
 * @param {string} [args.mission_s256]
 * @param {string} [args.tenant]
 * @param {number} [args.mission_expires_at] mission clamp, when known
 */
export async function issuePersonToken({
    agent_public_key,
    resource,
    lifetime = MAX_PERSON_TOKEN_TTL,
    agent_token_exp,
    mission_s256,
    tenant,
    mission_expires_at,
}) {
    const iat = Math.floor(Date.now() / 1000)

    // exp ≤ 1 hour, ≤ the agent token's exp, ≤ the mission's expires_at.
    let exp = iat + Math.min(lifetime, MAX_PERSON_TOKEN_TTL)
    if (Number.isFinite(agent_token_exp)) exp = Math.min(exp, agent_token_exp)
    if (Number.isFinite(mission_expires_at)) exp = Math.min(exp, mission_expires_at)

    const jti = randomUUID()

    // REQUIRED claims only, plus the two OPTIONAL ones. No `scope`, no
    // `account` — a person token conveys identity, never authorization.
    const payload = {
        iss: ISSUER,
        dwk: 'aauth-person.json',
        aud: resource,
        sub: directedSub(resource),
        cnf: { jwk: agent_public_key },
        jti,
        iat,
        exp,
    }
    if (mission_s256) payload.mission_s256 = mission_s256
    if (tenant) payload.tenant = tenant

    const person_token = await new SignJWT(payload)
        .setProtectedHeader({ alg: SIGNING_ALG, typ: 'aa-person+jwt', kid })
        .sign(privateKey)

    // §Resource Token Verification step 6 needs this later.
    recordPersonToken({
        jti,
        ps: ISSUER,
        sub: payload.sub,
        aud: resource,
        mission_s256: mission_s256 || undefined,
        tenant: tenant || undefined,
        exp,
    })

    return { person_token, expires_in: exp - iat }
}
