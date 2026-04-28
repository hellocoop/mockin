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
    generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint,
} from 'jose'
import { fetch as httpsigFetch } from '@hellocoop/httpsig'

import { ISSUER } from '../../src/config.js'

// ── Fake server identities ─────────────────────────────────────────────

async function mintServer(url, kid, alg = 'EdDSA') {
    const { publicKey, privateKey } = await generateKeyPair(alg, {
        crv: 'Ed25519',
    })
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
const ephemeralKp = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
export const ephemeralPublicJwk = await exportJWK(ephemeralKp.publicKey)
ephemeralPublicJwk.alg = 'EdDSA'
export const ephemeralPrivateJwk = await exportJWK(ephemeralKp.privateKey)
ephemeralPrivateJwk.alg = 'EdDSA'

export const ephemeralJkt = await calculateJwkThumbprint(ephemeralPublicJwk)

export const DEFAULT_AGENT_ID = `aauth:agent@${new URL(AGENT_SERVER_URL).host}`

// ── Mockin config registration ─────────────────────────────────────────
//
// Pushes both fake servers into mockin's trusted_servers map so its
// entity-cache resolves them without network. Also clears any prior mock
// state the previous test left behind.

export async function installMocks(fastify) {
    await fastify.inject({ method: 'DELETE', url: '/mock' })
    const trusted = {
        [AGENT_SERVER_URL]: {
            metadata: {
                issuer: AGENT_SERVER_URL,
                jwks_uri: `${AGENT_SERVER_URL}/.well-known/jwks.json`,
                client_name: 'Mock Agent Server',
            },
            jwks: { keys: [agentServer.publicJwk] },
        },
        [RESOURCE_SERVER_URL]: {
            metadata: {
                issuer: RESOURCE_SERVER_URL,
                jwks_uri: `${RESOURCE_SERVER_URL}/.well-known/jwks.json`,
                client_name: 'Mock Resource Server',
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
    ttl = 600,
} = {}) {
    const now = Math.floor(Date.now() / 1000)
    return await new SignJWT({
        iss: AGENT_SERVER_URL,
        dwk: 'aauth-agent.json',
        sub,
        ps,
        cnf: { jwk: cnf_jwk },
        iat: now,
        exp: now + ttl,
        jti: randomUUID(),
    })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-agent+jwt', kid: agentServer.kid })
        .sign(agentServer.privateKey)
}

export async function mintResourceToken({
    scope = 'openid email',
    aud = ISSUER,
    agent = DEFAULT_AGENT_ID,
    agent_jkt = ephemeralJkt,
    r3_uri = null,
    r3_s256 = null,
    ttl = 300,
} = {}) {
    const now = Math.floor(Date.now() / 1000)
    const payload = {
        iss: RESOURCE_SERVER_URL,
        dwk: 'aauth-resource.json',
        aud,
        agent,
        agent_jkt,
        scope,
        iat: now,
        exp: now + ttl,
        jti: randomUUID(),
    }
    if (r3_uri) payload.r3_uri = r3_uri
    if (r3_s256) payload.r3_s256 = r3_s256
    return await new SignJWT(payload)
        .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-resource+jwt', kid: resourceServer.kid })
        .sign(resourceServer.privateKey)
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

async function sigHeaders({ method, path, body, signatureKey }) {
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
    }
    const { headers } = await httpsigFetch(url, opts)
    const out = {}
    headers.forEach((v, k) => { out[k] = v })
    out.host = issuerHost
    return out
}

// JWT scheme — token, pending, permission, audit, interaction.
export async function signedRequest({
    method, path, body, agentToken,
}) {
    const bodyStr = body === undefined
        ? undefined
        : typeof body === 'string' ? body : JSON.stringify(body)
    const headers = await sigHeaders({
        method,
        path,
        body: bodyStr,
        signatureKey: { type: 'jwt', jwt: agentToken },
    })
    return { headers, payload: bodyStr }
}

// HWK scheme — bootstrap.
export async function signedHwkRequest({ method, path, body }) {
    const bodyStr = body === undefined
        ? undefined
        : typeof body === 'string' ? body : JSON.stringify(body)
    const headers = await sigHeaders({
        method,
        path,
        body: bodyStr,
        signatureKey: { type: 'hwk' },
    })
    return { headers, payload: bodyStr }
}
