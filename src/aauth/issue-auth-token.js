// aauth/issue-auth-token.js — sign an aa-auth+jwt for the agent.
//
// Mockin always issues against `defaultUser` — there is no real user pool.
// Identity scopes ('email', 'profile', etc.) become OIDC-Core claims on
// the token using values from defaultUser. Resource scopes ride as the
// space-separated `scope` claim. R3 grants are added when an R3 doc was
// presented.

import { randomUUID } from 'crypto'
import { SignJWT } from 'jose'

import { ISSUER } from '../config.js'
import { privateKey, kid } from './keys.js'
import { SIGNING_ALG } from './algorithms.js'
import { directedSub } from './subject.js'
import { getConfig } from './mock.js'
import defaultUser from '../users.js'

// "Auth tokens MUST NOT have a lifetime exceeding 1 hour."
const MAX_AUTH_TOKEN_TTL = 3600

const IDENTITY_SCOPES = new Set([
    'openid', 'profile', 'name', 'nickname', 'given_name', 'family_name',
    'preferred_username', 'picture', 'email', 'phone', 'phone_number',
    'address', 'birthdate', 'locale', 'zoneinfo',
    'tenant_sub', 'org', 'groups', 'roles',
    'github', 'gitlab', 'twitter', 'discord', 'ethereum',
])

export function classifyScopes(scopeStr) {
    const tokens = (scopeStr || '').split(/\s+/).filter(Boolean)
    const identity = []
    const resource = []
    for (const s of tokens) {
        if (IDENTITY_SCOPES.has(s)) identity.push(s)
        else resource.push(s)
    }
    return { identity, resource }
}

// Hellō's `profile` shorthand expands to name + email + picture (narrower
// than OIDC Core §5.4's full list). Mirror wallet's PROFILE_EXPANSION.
const PROFILE_EXPANSION = ['name', 'email', 'picture']

// Build a release payload from the mock user for the requested identity scopes.
function releaseFor(identityScopes) {
    const payload = {}
    const u = defaultUser
    // Profile expands inline so its members go through the same per-scope
    // handlers below (e.g. so `profile` still triggers email_verified).
    const expanded = []
    for (const s of identityScopes) {
        if (s === 'profile') expanded.push(...PROFILE_EXPANSION)
        else expanded.push(s)
    }
    for (const s of expanded) {
        if (s === 'openid') continue
        // OIDC `email` scope releases `email` and `email_verified`.
        if (s === 'email') {
            if (u.email !== undefined) payload.email = u.email
            payload.email_verified = u.email_verified ?? true
            continue
        }
        // OIDC `phone` scope releases `phone_number` and `phone_number_verified`.
        // The mock user stores the number under `phone`.
        if (s === 'phone') {
            const num = u.phone_number ?? u.phone
            if (num !== undefined) payload.phone_number = num
            payload.phone_number_verified = u.phone_number_verified ?? true
            continue
        }
        // OIDC `address` is structured.
        if (s === 'address') {
            if (u.address !== undefined) payload.address = u.address
            continue
        }
        if (u[s] !== undefined) payload[s] = u[s]
    }
    return payload
}

/**
 * -11 §Auth Token Structure. REQUIRED: iss, dwk, aud, jti, ps, sub, cnf,
 * iat, exp. No `agent` claim, no `act`, no delegation chain — the resource
 * enforces against `sub` and `scope`, and `cnf` binds the key.
 *
 * @param {object} args
 * @param {object} args.agent_public_key    ephemeral JWK for cnf
 * @param {string} args.resource_url        resource_token.iss — becomes `aud`
 * @param {string} args.scope               raw scope string from resource_token
 * @param {string} [args.sub]               copied from the resource token, which
 *                                          the PS verified against the person
 *                                          token it issued. Falls back to the
 *                                          same derivation the person token used.
 * @param {string} [args.mission_s256]      copied from the resource token
 * @param {string} [args.tenant]            copied from the resource token
 * @param {string} [args.account]           copied from the resource token
 * @param {number} [args.presented_exp]     exp of the presented_token the
 *                                          request carried — the auth token
 *                                          MUST NOT expire later (-11 §Auth
 *                                          Token Structure, issue #152)
 * @param {object} [args.r3]                { uri, s256, granted, per_call }
 */
export async function issueAuthToken({
    agent_public_key,
    resource_url,
    scope,
    sub,
    mission_s256,
    tenant,
    account,
    presented_exp,
    r3,
}) {
    const cfg = getConfig()
    const iat = Math.floor(Date.now() / 1000)
    let lifetime = Math.min(cfg.token_lifetime || MAX_AUTH_TOKEN_TTL, MAX_AUTH_TOKEN_TTL)
    if (Number.isFinite(presented_exp)) {
        lifetime = Math.max(1, Math.min(lifetime, presented_exp - iat))
    }
    const { identity, resource } = classifyScopes(scope)

    const release = releaseFor(identity)
    const claimsOverride = cfg.claims || {}

    const tokenPayload = {
        iss: ISSUER,
        dwk: 'aauth-person.json',
        ps: ISSUER,
        // Same value the person token carried for this aud — see subject.js.
        sub: sub || directedSub(resource_url),
        aud: resource_url,
        scope: resource.join(' '),
        cnf: agent_public_key ? { jwk: agent_public_key } : undefined,
        ...release,
        ...claimsOverride,
        iat,
        exp: iat + lifetime,
    }

    if (mission_s256) tokenPayload.mission_s256 = mission_s256
    if (tenant) tokenPayload.tenant = tenant
    if (account) tokenPayload.account = account

    if (r3) {
        if (r3.uri) tokenPayload.r3_uri = r3.uri
        if (r3.s256) tokenPayload.r3_s256 = r3.s256
        if (r3.granted) tokenPayload.r3_granted = r3.granted
        // R3 -02 renamed r3_conditional → r3_per_call.
        if (r3.per_call) tokenPayload.r3_per_call = r3.per_call
    }

    const auth_token = await new SignJWT(tokenPayload)
        .setProtectedHeader({ alg: SIGNING_ALG, typ: 'aa-auth+jwt', kid })
        .setJti(randomUUID())
        .sign(privateKey)

    return { auth_token, expires_in: lifetime }
}
