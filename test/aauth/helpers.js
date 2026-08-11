// test/aauth/helpers.js — shared utilities for AAuth tests.
//
// What the tests need to do, end-to-end:
//   1. Stand up a fake agent server (AS) and a fake resource server (RS),
//      each with its own Ed25519 keypair, JWKS, and well-known metadata.
//   2. Tell mockin about them via mock.trusted_servers so it skips network
//      JWKS fetches.
//   3. Mint an agent_token (signed by AS, cnf.jwk = ephemeral) and a
//      resource_token (signed by RS, aud = mockin) for each test case.
//   4. Sign the HTTP request to mockin with the ephemeral key, presenting
//      the agent_token via Signature-Key: sig=jwt.
//
// All of this stays in-process; tests use fastify.inject() and never open
// a port or hit the network.

import { createHash, randomUUID } from 'crypto'
import {
    generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint, decodeJwt,
} from 'jose'
import { fetch as httpsigFetch } from '@hellocoop/httpsig'

import { ISSUER } from '../../src/config.js'

// ── Fake server identities ─────────────────────────────────────────────

// httpsig 2.0 (RFC 9864): alg must be fully specified — 'Ed25519', never
// the polymorphic 'EdDSA'.
async function mintServer(url, kid, alg = 'Ed25519') {
    const { publicKey, privateKey } = await generateKeyPair(alg)
    const publicJwk = await exportJWK(publicKey)
    publicJwk.kid = kid
    publicJwk.alg = alg
    publicJwk.use = 'sig'
    const privateJwk = await exportJWK(privateKey)
    privateJwk.kid = kid
    privateJwk.alg = alg
    return { url, kid, publicKey, privateKey, publicJwk, privateJwk }
}

export const AGENT_SERVER_URL = 'https://as.example'
export const RESOURCE_SERVER_URL = 'https://rs.example'

export const agentServer = await mintServer(AGENT_SERVER_URL, 'as-key-1')
export const resourceServer = await mintServer(RESOURCE_SERVER_URL, 'rs-key-1')

// Ephemeral key the "agent" uses to sign HTTP requests.
const ephemeralKp = await generateKeyPair('Ed25519')
export const ephemeralPublicJwk = await exportJWK(ephemeralKp.publicKey)
ephemeralPublicJwk.alg = 'Ed25519'
export const ephemeralPrivateJwk = await exportJWK(ephemeralKp.privateKey)
ephemeralPrivateJwk.alg = 'Ed25519'

export const ephemeralJkt = await calculateJwkThumbprint(ephemeralPublicJwk)

export const DEFAULT_AGENT_ID = `aauth:agent@${new URL(AGENT_SERVER_URL).host}`

// ── Mockin config registration ─────────────────────────────────────────
//
// Pushes both fake servers into mockin's trusted_servers map so its
// entity-cache resolves them without network. Also clears any prior mock
// state the previous test left behind.

export async function installMocks(fastify) {
    await fastify.inject({ method: 'DELETE', url: '/mock' })
    // Agent and resource metadata publish `name`, never `client_name` —
    // the RFC 7591 borrowing appears nowhere in the AAuth specs.
    const trusted = {
        [AGENT_SERVER_URL]: {
            metadata: {
                issuer: AGENT_SERVER_URL,
                jwks_uri: `${AGENT_SERVER_URL}/.well-known/jwks.json`,
                name: 'Mock Agent Server',
            },
            jwks: { keys: [agentServer.publicJwk] },
        },
        [RESOURCE_SERVER_URL]: {
            metadata: {
                issuer: RESOURCE_SERVER_URL,
                jwks_uri: `${RESOURCE_SERVER_URL}/.well-known/jwks.json`,
                name: 'Mock Resource Server',
                scope_descriptions: { whoami: 'Read identity' },
            },
            jwks: { keys: [resourceServer.publicJwk] },
        },
    }
    await fastify.inject({
        method: 'PUT',
        url: '/mock/aauth',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ trusted_servers: trusted }),
    })
}

// ── Token minting ──────────────────────────────────────────────────────

export async function mintAgentToken({
    sub = DEFAULT_AGENT_ID,
    ps = ISSUER,
    cnf_jwk = ephemeralPublicJwk,
    parent_agent = undefined,
    ttl = 600,
    // -10 forbids the polymorphic 'EdDSA'; tests override this to prove
    // mockin declines it.
    alg = 'Ed25519',
} = {}) {
    const now = Math.floor(Date.now() / 1000)
    const payload = {
        iss: AGENT_SERVER_URL,
        dwk: 'aauth-agent.json',
        sub,
        ps,
        cnf: { jwk: cnf_jwk },
        iat: now,
        exp: now + ttl,
        jti: randomUUID(),
    }
    if (parent_agent) payload.parent_agent = parent_agent
    return await new SignJWT(payload)
        .setProtectedHeader({ alg, typ: 'aa-agent+jwt', kid: agentServer.kid })
        .sign(agentServer.privateKey)
}

// -11 §Resource Token Structure: `ps`, `sub` and `person_token_jti` are
// copied from the person token the resource verified, `agent_jkt` binds
// the agent's key. There is no `agent` claim any more.
export async function mintResourceToken({
    scope = 'openid email',
    aud = ISSUER,
    ps = ISSUER,
    sub,
    person_token_jti,
    agent_jkt = ephemeralJkt,
    mission_s256 = null,
    tenant = null,
    account = null,
    r3_uri = null,
    r3_s256 = null,
    ttl = 300,
    personToken = null,
} = {}) {
    // Given a person token, copy from it — the normal case. Pass `false`
    // for any field to omit it deliberately (what a resource stripping a
    // claim would produce), or a value to make it disagree.
    if (personToken) {
        const pt = decodeJwt(personToken)
        sub = sub ?? pt.sub
        person_token_jti = person_token_jti ?? pt.jti
        ps = ps ?? pt.iss
        if (mission_s256 === null && pt.mission_s256) mission_s256 = pt.mission_s256
        if (tenant === null && pt.tenant) tenant = pt.tenant
    }
    const now = Math.floor(Date.now() / 1000)
    const payload = {
        iss: RESOURCE_SERVER_URL,
        dwk: 'aauth-resource.json',
        aud,
        ps,
        sub,
        person_token_jti,
        agent_jkt,
        scope,
        iat: now,
        exp: now + ttl,
        jti: randomUUID(),
    }
    for (const k of ['ps', 'sub', 'person_token_jti']) {
        if (!payload[k]) delete payload[k]
    }
    if (mission_s256) payload.mission_s256 = mission_s256
    if (tenant) payload.tenant = tenant
    if (account) payload.account = account
    if (r3_uri) payload.r3_uri = r3_uri
    if (r3_s256) payload.r3_s256 = r3_s256
    return await new SignJWT(payload)
        .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-resource+jwt', kid: resourceServer.kid })
        .sign(resourceServer.privateKey)
}

// ── Person tokens ──────────────────────────────────────────────────────
//
// Almost every /aauth/token test now needs one first: the PS will only
// accept a resource token whose person_token_jti names a person token it
// issued (§Resource Token Verification step 6).

export async function requestPersonToken(fastify, {
    resource = RESOURCE_SERVER_URL,
    agentToken,
    ...rest
} = {}) {
    const token = agentToken || (await mintAgentToken())
    const { headers, payload } = await signedRequest({
        method: 'POST',
        path: '/aauth/person',
        body: { resource, ...rest },
        agentToken: token,
    })
    return fastify.inject({
        method: 'POST',
        url: '/aauth/person',
        headers,
        payload,
    })
}

/** 200-path convenience: returns { person_token, claims, agentToken }. */
export async function getPersonToken(fastify, options = {}) {
    const agentToken = options.agentToken || (await mintAgentToken())
    const res = await requestPersonToken(fastify, { ...options, agentToken })
    if (res.statusCode !== 200) {
        throw new Error(
            `person token request failed: ${res.statusCode} ${res.payload}`,
        )
    }
    const { person_token, expires_in } = res.json()
    return {
        person_token,
        expires_in,
        claims: decodeJwt(person_token),
        agentToken,
    }
}

/**
 * The common setup: get a person token, then a resource token copied from
 * it. Overrides let a test corrupt exactly one copied claim.
 */
export async function personAndResourceToken(fastify, {
    person = {},
    resource = {},
} = {}) {
    const { person_token, claims, agentToken } = await getPersonToken(fastify, person)
    const resourceToken = await mintResourceToken({
        personToken: person_token,
        ...resource,
    })
    return { agentToken, person_token, personClaims: claims, resourceToken }
}

// ── R3 doc helpers ─────────────────────────────────────────────────────

export function r3Hash(bodyStr) {
    return createHash('sha256').update(bodyStr).digest('base64url')
}

// Pre-register an R3 doc against the resource server's trusted entry so
// mockin's r3.fetchR3Document hits the in-memory bypass.
export async function registerR3Document(fastify, r3_uri, document) {
    const cfg = (
        await fastify.inject({ method: 'GET', url: '/mock/aauth' })
    ).json()
    const trusted = { ...(cfg.trusted_servers || {}) }
    const rsEntry = { ...(trusted[RESOURCE_SERVER_URL] || {}) }
    const r3Docs = { ...(rsEntry.r3_documents || {}) }
    const bodyStr = typeof document === 'string'
        ? document
        : JSON.stringify(document)
    r3Docs[r3_uri] = bodyStr
    rsEntry.r3_documents = r3Docs
    trusted[RESOURCE_SERVER_URL] = rsEntry
    await fastify.inject({
        method: 'PUT',
        url: '/mock/aauth',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ trusted_servers: trusted }),
    })
    return { r3_uri, r3_s256: r3Hash(bodyStr), bodyStr }
}

// ── Request signing ────────────────────────────────────────────────────

const issuerHost = new URL(ISSUER).host

// -11: a request carrying a body to a PS endpoint MUST sign
// `content-digest` and `content-type`. httpsig only generates
// Content-Digest when the covered-component list names it, and its
// DEFAULT_COMPONENTS_BODY does not — so pass the list explicitly.
export const PS_BODY_COMPONENTS = [
    '@method', '@authority', '@path',
    'content-type', 'content-digest',
    'signature-key',
]

async function sigHeaders({ method, path, body, signatureKey, components }) {
    const url = `${ISSUER}${path}`
    const opts = {
        method,
        signingKey: ephemeralPrivateJwk,
        signatureKey,
        dryRun: true,
    }
    if (body !== undefined) {
        opts.headers = { 'content-type': 'application/json' }
        opts.body = body
        opts.components = components || PS_BODY_COMPONENTS
    } else if (components) {
        opts.components = components
    }
    const { headers } = await httpsigFetch(url, opts)
    const out = {}
    headers.forEach((v, k) => { out[k] = v })
    out.host = issuerHost
    return out
}

// JWT scheme — person, token, pending, permission, audit, interaction.
export async function signedRequest({
    method, path, body, agentToken, components,
}) {
    const bodyStr = body === undefined
        ? undefined
        : typeof body === 'string' ? body : JSON.stringify(body)
    const headers = await sigHeaders({
        method,
        path,
        body: bodyStr,
        components,
        signatureKey: { type: 'jwt', jwt: agentToken },
    })
    return { headers, payload: bodyStr }
}

// HWK scheme — bootstrap.
export async function signedHwkRequest({ method, path, body, components }) {
    const bodyStr = body === undefined
        ? undefined
        : typeof body === 'string' ? body : JSON.stringify(body)
    const headers = await sigHeaders({
        method,
        path,
        body: bodyStr,
        components,
        signatureKey: { type: 'hwk' },
    })
    return { headers, payload: bodyStr }
}
