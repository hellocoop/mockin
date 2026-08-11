// aauth/r3.js — R3 (Rich Resource Requests) document fetch + hash verify.
//
// When a resource_token carries r3_uri + r3_s256, the PS fetches the R3
// document, verifies SHA-256 of the raw bytes matches r3_s256, and uses
// the document's `operations` to populate the auth_token's r3_granted /
// r3_per_call claims. (R3 -02 renamed `r3_conditional` to `r3_per_call`.)
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

// The seven standard vocabularies of R3 -02. `openapi-gateway` was removed
// in -02 and is no longer accepted; third-party vocabularies use their own
// URI namespace and are passed through.
export const STANDARD_VOCABULARIES = new Set([
    'urn:aauth:vocabulary:mcp',
    'urn:aauth:vocabulary:openapi',
    'urn:aauth:vocabulary:grpc',
    'urn:aauth:vocabulary:graphql',
    'urn:aauth:vocabulary:asyncapi',
    'urn:aauth:vocabulary:wsdl',
    'urn:aauth:vocabulary:odata',
])

/** @returns {string|null} an error message, or null when the document is valid. */
export function validateR3Document(document) {
    if (!document || typeof document !== 'object' || Array.isArray(document)) {
        return 'r3 document must be a JSON object'
    }
    if (typeof document.vocabulary !== 'string' || !document.vocabulary) {
        return 'r3 document missing vocabulary'
    }
    if (
        document.vocabulary.startsWith('urn:aauth:vocabulary:') &&
        !STANDARD_VOCABULARIES.has(document.vocabulary)
    ) {
        return `unknown vocabulary "${document.vocabulary}" (R3 -02 defines seven; openapi-gateway was removed)`
    }
    if (!Array.isArray(document.operations) || document.operations.length === 0) {
        return 'r3 document missing operations'
    }
    // A per-call proposal is a full R3 document plus a REQUIRED
    // `parameters` object. Nothing else distinguishes it, so a document
    // carrying a non-object `parameters` is malformed rather than a class
    // document with a stray field.
    if (
        'parameters' in document &&
        (typeof document.parameters !== 'object' ||
            document.parameters === null ||
            Array.isArray(document.parameters))
    ) {
        return 'r3 per-call proposal parameters must be an object'
    }
    return null
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
            const preloaded = JSON.parse(bytes.toString('utf8'))
            const invalid = validateR3Document(preloaded)
            if (invalid) return new Error(invalid)
            return { document: preloaded, bytes }
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
    const invalid = validateR3Document(document)
    if (invalid) return new Error(invalid)
    return { document, bytes }
}

// R3 -02 §Per-Call Proposals: a proposal is a full R3 document for one
// pending call, distinguished by a REQUIRED `parameters` object carrying
// that call's concrete arguments. `version` is no longer a document field,
// and the `openapi-gateway` vocabulary no longer exists.
export function isPerCallProposal(document) {
    return Boolean(
        document &&
        typeof document.parameters === 'object' &&
        document.parameters !== null &&
        !Array.isArray(document.parameters),
    )
}

// Mockin's auto-grant: every op in the document goes into r3_granted,
// r3_per_call stays empty. A per-call proposal is approved for the one
// call it describes — the flow ends with the proposed operation in
// r3_granted, not in r3_per_call. Override via mock.r3_grants for tests.
export function autoGrantR3({ document }) {
    const override = getConfig().r3_grants
    if (override) {
        return {
            granted: override.granted || null,
            per_call: override.per_call || null,
        }
    }
    if (!document?.operations || !Array.isArray(document.operations)) {
        return { granted: null, per_call: null }
    }
    return {
        granted: {
            vocabulary: document.vocabulary,
            operations: document.operations,
        },
        per_call: null,
    }
}
