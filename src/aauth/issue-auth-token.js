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
import { getConfig } from './mock.js'
import defaultUser from '../users.js'

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
 * @param {object} args
 * @param {string} args.agent_id
 * @param {object} args.agent_public_key   ephemeral JWK for cnf
 * @param {string} args.resource_url       resource_token.iss
 * @param {string} args.scope              raw scope string from resource_token
 * @param {object} [args.r3]               { uri, s256, granted, conditional }
 */
export async function issueAuthToken({
    agent_id,
    agent_public_key,
    resource_url,
    scope,
    r3,
}) {
    const cfg = getConfig()
    const lifetime = cfg.token_lifetime || 3600
    const { identity, resource } = classifyScopes(scope)

    const release = releaseFor(identity)
    const claimsOverride = cfg.claims || {}

    const iat = Math.floor(Date.now() / 1000)
    const tokenPayload = {
        iss: ISSUER,
        dwk: 'aauth-person.json',
        sub: defaultUser.sub,
        aud: resource_url,
        agent: agent_id,
        act: { sub: agent_id },
        scope: resource.join(' '),
        cnf: agent_public_key ? { jwk: agent_public_key } : undefined,
        ...release,
        ...claimsOverride,
        iat,
        exp: iat + lifetime,
    }

    if (r3) {
        if (r3.uri) tokenPayload.r3_uri = r3.uri
        if (r3.s256) tokenPayload.r3_s256 = r3.s256
        if (r3.granted) tokenPayload.r3_granted = r3.granted
        if (r3.conditional) tokenPayload.r3_conditional = r3.conditional
    }

    const auth_token = await new SignJWT(tokenPayload)
        .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-auth+jwt', kid })
        .setJti(randomUUID())
        .sign(privateKey)

    return { auth_token, expires_in: lifetime }
}
