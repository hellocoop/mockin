// test/aauth/helpers.js — shared test utilities for AAuth tests

import { generateKeyPair, exportJWK } from 'jose'
import { fetch as httpsigFetch } from '@hellocoop/httpsig'
import { ISSUER } from '../../src/config.js'

// Generate a test agent Ed25519 key pair
const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
export const agentPublicJwk = await exportJWK(publicKey)
export const agentPrivateJwk = await exportJWK(privateKey)

/**
 * Generate signed headers for a POST request using httpsig dry-run mode.
 * Returns headers object suitable for fastify.inject().
 */
export async function signedPost(path, body, opts = {}) {
    const url = `${ISSUER}${path}`
    const bodyStr = typeof body === 'string' ? body : JSON.stringify(body)

    const { headers } = await httpsigFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: bodyStr,
        signingKey: opts.signingKey || agentPrivateJwk,
        signatureKey: opts.signatureKey || { type: 'hwk' },
        dryRun: true,
    })

    // Convert Headers to plain object for fastify.inject
    const headerObj = {}
    headers.forEach((value, key) => {
        headerObj[key] = value
    })

    // Set host header to match the authority used for signing
    const issuerUrl = new URL(ISSUER)
    headerObj['host'] = issuerUrl.host

    return { headers: headerObj, payload: bodyStr }
}

/**
 * Generate signed headers for a GET request using httpsig dry-run mode.
 * Returns headers object suitable for fastify.inject().
 */
export async function signedGet(path, opts = {}) {
    const url = `${ISSUER}${path}`

    const { headers } = await httpsigFetch(url, {
        method: 'GET',
        signingKey: opts.signingKey || agentPrivateJwk,
        signatureKey: opts.signatureKey || { type: 'hwk' },
        dryRun: true,
    })

    // Convert Headers to plain object for fastify.inject
    const headerObj = {}
    headers.forEach((value, key) => {
        headerObj[key] = value
    })

    // Set host header to match the authority used for signing
    const issuerUrl = new URL(ISSUER)
    headerObj['host'] = issuerUrl.host

    return { headers: headerObj }
}
