// aauth/verify-presented-token.js — step 6 of §Resource Token Verification.
//
// Protocol -11 (issue #152): the agent's auth token request carries
// `presented_token`, the token it presented to the resource that issued the
// resource token — the person token on the first challenge of a grant, or
// the auth token on a step-up / per-call challenge. The resource copied
// `ps`, `sub`, `mission_s256` and `tenant` out of it and named it by
// `presented_jti`. The PS verifies the presented token by its `typ`:
//
//   aa-person+jwt  — a person token this PS issued (iss = ISSUER)
//   aa-auth+jwt    — an auth token; issued by this PS on a three-party
//                    step-up, or by an Access Server in four-party. `ps`
//                    MUST name this PS. (mockin has no AS federation, so
//                    an AS-issued auth token verifies against the AS's
//                    JWKS only if the AS is a trusted server.)
//
// with two substitutions from the resource's own check: `aud` MUST equal
// the resource token's `iss`, and `cnf.jwk` MUST match the resource token's
// `agent_jkt`. A token that fails is `invalid_presented_token`, or
// `expired_presented_token` when only `exp` fails. Then the binding: `jti`
// equals `presented_jti`, `iss` (person) / `ps` (auth) equals the resource
// token's `ps`, and `sub`, `mission_s256`, `tenant` match exactly — any
// mismatch or omission is `invalid_resource_token`. This is what makes
// mission stripping detectable: the agent hands the PS the token the
// resource verified, under its issuer's signature, and the PS compares.
//
// No retained record is consulted. person-token-store.js keeps the
// jti/aud/exp the spec requires for revocation, nothing more.

import * as jose from 'jose'
import { ISSUER } from '../config.js'
import { publicJwk } from './keys.js'
import { ACCEPTED_JWT_ALGS, checkJwtAlg } from './algorithms.js'
import { getEntity, PERSON_DWK } from './entity-cache.js'

export const ACCESS_DWK = 'aauth-access.json'

const PERSON_TYP = 'aa-person+jwt'
const AUTH_TYP = 'aa-auth+jwt'

const fail = (code, error) => ({ code, error })

/**
 * @param {string} presentedTokenStr  the `presented_token` body parameter
 * @param {object} rt                  the verified resource token: resource_url,
 *                                     ps, sub, mission_s256, tenant,
 *                                     presented_jti, agent_jkt
 * @returns {{ code: string, error: string } |
 *   { kind: 'person'|'auth', jti: string, exp: number, ps: string, sub: string,
 *     mission_s256: string|null, tenant: string|null, payload: object }}
 */
export async function verifyPresentedToken(presentedTokenStr, rt) {
    if (typeof presentedTokenStr !== 'string' || !presentedTokenStr) {
        return fail('invalid_presented_token', 'presented_token must be a JWT')
    }
    let header, payload
    try {
        header = jose.decodeProtectedHeader(presentedTokenStr)
        payload = jose.decodeJwt(presentedTokenStr)
    } catch {
        return fail('invalid_presented_token', 'malformed presented_token')
    }

    let kind
    if (header.typ === PERSON_TYP) kind = 'person'
    else if (header.typ === AUTH_TYP) kind = 'auth'
    else {
        return fail(
            'invalid_presented_token',
            `invalid presented_token typ: expected ${PERSON_TYP} or ${AUTH_TYP}, got ${header.typ}`,
        )
    }
    const algError = checkJwtAlg(header.alg)
    if (algError) return fail('invalid_presented_token', `presented_token ${algError}`)

    // The PS whose person the token is for MUST be this PS.
    const psClaim = kind === 'person' ? payload.iss : payload.ps
    if (psClaim !== ISSUER) {
        return fail(
            'invalid_presented_token',
            kind === 'person'
                ? `presented person token iss "${payload.iss}" was not issued by this PS`
                : `presented auth token ps "${payload.ps}" does not name this PS`,
        )
    }

    // Key: our own for anything we issued; the issuer's JWKS otherwise
    // (an AS-issued auth token on a four-party step-up).
    let keyset
    if (payload.iss === ISSUER) {
        if (payload.dwk !== PERSON_DWK) {
            return fail(
                'invalid_presented_token',
                `presented_token dwk must be ${PERSON_DWK}, got ${payload.dwk}`,
            )
        }
        keyset = jose.createLocalJWKSet({ keys: [publicJwk] })
    } else {
        if (payload.dwk !== ACCESS_DWK) {
            return fail(
                'invalid_presented_token',
                `presented auth token dwk must be ${ACCESS_DWK}, got ${payload.dwk}`,
            )
        }
        let entity
        try {
            entity = await getEntity(payload.iss, ACCESS_DWK)
        } catch (err) {
            return fail(
                'invalid_presented_token',
                `presented auth token issuer discovery failed: ${err.message}`,
            )
        }
        keyset = jose.createLocalJWKSet(entity.jwks)
    }

    // jose verifies the signature before any claim, so JWTExpired means
    // everything but exp held — the expired_presented_token case.
    try {
        await jose.jwtVerify(presentedTokenStr, keyset, {
            algorithms: ACCEPTED_JWT_ALGS,
        })
    } catch (err) {
        if (err.code === 'ERR_JWT_EXPIRED') {
            return fail(
                'expired_presented_token',
                'presented_token expired: obtain a fresh person token, then a fresh resource token',
            )
        }
        return fail(
            'invalid_presented_token',
            `presented_token signature: ${err.message}`,
        )
    }

    // The two substitutions.
    const audOk = Array.isArray(payload.aud)
        ? payload.aud.includes(rt.resource_url)
        : payload.aud === rt.resource_url
    if (!audOk) {
        return fail(
            'invalid_presented_token',
            `presented_token aud mismatch: expected the resource ${rt.resource_url}, got ${payload.aud}`,
        )
    }
    const cnfJwk = payload.cnf?.jwk
    if (!cnfJwk) {
        return fail('invalid_presented_token', 'presented_token missing cnf.jwk')
    }
    let jkt
    try {
        jkt = await jose.calculateJwkThumbprint(cnfJwk)
    } catch {
        return fail('invalid_presented_token', 'presented_token cnf.jwk is not a valid key')
    }
    if (jkt !== rt.agent_jkt) {
        return fail(
            'invalid_presented_token',
            `presented_token cnf.jwk thumbprint ${jkt} does not match resource_token agent_jkt ${rt.agent_jkt}`,
        )
    }
    if (!payload.jti) return fail('invalid_presented_token', 'presented_token missing jti')
    if (!payload.sub) return fail('invalid_presented_token', 'presented_token missing sub')

    // Binding to the resource token.
    if (payload.jti !== rt.presented_jti) {
        return fail(
            'invalid_resource_token',
            `resource_token presented_jti "${rt.presented_jti}" does not name the presented token (jti "${payload.jti}")`,
        )
    }
    if (rt.ps !== psClaim) {
        return fail(
            'invalid_resource_token',
            `resource_token ps mismatch: presented token has ${psClaim}, resource_token has ${rt.ps}`,
        )
    }
    if (rt.sub !== payload.sub) {
        return fail(
            'invalid_resource_token',
            `resource_token sub mismatch: presented token has ${payload.sub}, resource_token has ${rt.sub}`,
        )
    }
    // A dropped mission_s256 is exactly the stripping this check exists to
    // catch, so absent-vs-present is a mismatch in both directions.
    const mission = payload.mission_s256 || null
    if ((rt.mission_s256 || null) !== mission) {
        return fail(
            'invalid_resource_token',
            `resource_token mission_s256 mismatch: presented token has ${mission || '(none)'}, resource_token has ${rt.mission_s256 || '(none)'}`,
        )
    }
    const tenant = payload.tenant || null
    if ((rt.tenant || null) !== tenant) {
        return fail(
            'invalid_resource_token',
            `resource_token tenant mismatch: presented token has ${tenant || '(none)'}, resource_token has ${rt.tenant || '(none)'}`,
        )
    }

    return {
        kind,
        jti: payload.jti,
        exp: payload.exp,
        ps: psClaim,
        sub: payload.sub,
        mission_s256: mission,
        tenant,
        payload,
    }
}
