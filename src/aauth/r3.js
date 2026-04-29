// aauth/r3.js — R3 (Rich Resource Requests) document fetch + hash verify.
//
// When a resource_token carries r3_uri + r3_s256, the PS fetches the R3
// document, verifies SHA-256 of the raw bytes matches r3_s256, and uses
// the document's `operations` to populate the auth_token's r3_granted /
// r3_conditional claims.
//
// Per draft-hardt-aauth-r3 §Security Considerations, the resource MUST
// require a valid HTTP Message Signature on R3 document URIs and reject
// any request not signed by its AS (in our deployment, the PS). So this
// fetch goes out HTTP-signed with sig=jwks_uri — the resource resolves
// our key by fetching ${ISSUER}/.well-known/aauth-person.json → jwks_uri,
// which is the same metadata we already publish for token verification.
//
// Mockin's PS auto-grants every operation in the document — there is no
// user-facing consent step. Tests can override via mock.r3_grants.

import { createHash } from 'crypto'
import { fetch as sigFetch } from '@hellocoop/httpsig'
import { getConfig } from './mock.js'
import { privateJwk, privateKey, kid } from './keys.js'
import { ISSUER } from '../config.js'

export function sha256B64url(bytes) {
    const buf = bytes instanceof ArrayBuffer ? Buffer.from(bytes) : bytes
    return createHash('sha256').update(buf).digest('base64url')
}

export async function fetchR3Document({ r3_uri, expected_s256 }) {
    const trusted = getConfig().trusted_servers || {}
    // Tests can preload an R3 doc by URI to bypass network.
    for (const entry of Object.values(trusted)) {
        if (entry?.r3_documents?.[r3_uri]) {
            const doc = entry.r3_documents[r3_uri]
            const bytes = Buffer.from(
                typeof doc === 'string' ? doc : JSON.stringify(doc),
            )
            const actual = sha256B64url(bytes)
            if (actual !== expected_s256) {
                return new Error(
                    `r3_s256 mismatch (preloaded): expected ${expected_s256}, got ${actual}`,
                )
            }
            return { document: JSON.parse(bytes.toString('utf8')), bytes }
        }
    }

    let response
    try {
        response = await sigFetch(r3_uri, {
            method: 'GET',
            signingKey: privateJwk,
            signingCryptoKey: privateKey,
            signatureKey: {
                type: 'jwks_uri',
                id: ISSUER,
                kid,
                dwk: 'aauth-person.json',
            },
            components: ['@method', '@authority', '@path', 'signature-key'],
        })
    } catch (err) {
        return new Error(`r3 fetch error: ${err.message}`)
    }
    if (!response.ok) {
        return new Error(`r3 fetch returned ${response.status}`)
    }
    const ab = await response.arrayBuffer()
    const bytes = Buffer.from(ab)
    const actual = sha256B64url(bytes)
    if (actual !== expected_s256) {
        return new Error(
            `r3_s256 mismatch: expected ${expected_s256}, got ${actual}`,
        )
    }
    let document
    try {
        document = JSON.parse(bytes.toString('utf8'))
    } catch (err) {
        return new Error(`r3 document not JSON: ${err.message}`)
    }
    return { document, bytes }
}

// Mockin's auto-grant: every op in the document goes into r3_granted,
// r3_conditional stays empty. Override via mock.r3_grants for tests.
export function autoGrantR3({ document }) {
    const override = getConfig().r3_grants
    if (override) {
        return {
            granted: override.granted || null,
            conditional: override.conditional || null,
        }
    }
    if (!document?.operations || !Array.isArray(document.operations)) {
        return { granted: null, conditional: null }
    }
    return {
        granted: {
            vocabulary: document.vocabulary,
            operations: document.operations,
        },
        conditional: null,
    }
}
