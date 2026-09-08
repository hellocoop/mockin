// aauth/verify-request.js — HTTPSig + agent_token verification.
//
// Every agent-facing AAuth endpoint runs the incoming request through this:
//
//   1. RFC9421 signature verification (Signature-Input + Signature)
//   2. Covered components: a request with a body to a PS endpoint MUST
//      sign `content-digest` and `content-type` (-11 §HTTP Message
//      Signatures Profile). httpsig verifies the digest itself once the
//      component is covered; it is the *coverage* we have to insist on.
//   3. The Signature-Key MUST use scheme=jwt and present an aa-agent+jwt
//   4. The agent_token's signature MUST verify against its issuer's JWKS
//   5. Header/claim sanity (typ, alg, iss, exp, cnf.jwk presence)
//
// On failure the helper returns a tuple describing the response so the
// handler can `return reply.code(...).headers(...).send(...)`. On success
// it returns identity/key material derived from the verified JWT.

import {
    verify as httpSigVerify,
    generateSignatureErrorHeader,
    generateAcceptSignatureHeader,
    generateAcceptSignatureSchemeHeader,
    generateAcceptSignatureAlgHeader,
} from '@hellocoop/httpsig'

import { verifyAgentToken } from './verify-agent-token.js'
import { ACCEPTED_JWT_ALGS } from './algorithms.js'
import { getConfig } from './mock.js'
import { problemBody, PROBLEM_CONTENT_TYPE } from './problem.js'

// -11: PS endpoints taking a body require content-digest and content-type
// in the covered components, on top of the base profile.
export const BODY_COMPONENTS = [
    '@method', '@authority', '@path',
    'content-type', 'content-digest',
    'signature-key',
]
export const NOBODY_COMPONENTS = [
    '@method', '@authority', '@path', 'signature-key',
]

export const ACCEPT_SIG_BODY = generateAcceptSignatureHeader({
    label: 'sig',
    components: BODY_COMPONENTS,
})

export const ACCEPT_SIG_NOBODY = generateAcceptSignatureHeader({
    label: 'sig',
    components: NOBODY_COMPONENTS,
})

// -08 replaced Accept-Signature's sigkey parameter with a separate
// Accept-Signature-Scheme header. These endpoints require sig=jwt.
export const ACCEPT_SIG_SCHEME = generateAcceptSignatureSchemeHeader(['jwt'])

// -10 admits no polymorphic EdDSA; say so when we decline one.
export const ACCEPT_SIG_ALG = generateAcceptSignatureAlgHeader(ACCEPTED_JWT_ALGS)

// Failures carry an RFC 9457 problem body (§Error Response Format): the
// AAuth code in `error`, the explanation in `detail`. verifyPreHandler
// sets the content type when it sends one.
function fail(status, error, detail, headers = {}) {
    return { ok: false, status, body: problemBody(error, detail), headers }
}

/**
 * The components covered by the `sig` signature, read straight off
 * Signature-Input. httpsig does not report them on its result, and the
 * profile requirement is about coverage, so we parse them here.
 *   sig=("@method" "@authority" "@path" "content-digest");created=…
 */
export function coveredComponents(signatureInput, label = 'sig') {
    if (!signatureInput) return []
    const match = new RegExp(`(?:^|,\\s*)${label}=\\(([^)]*)\\)`).exec(
        Array.isArray(signatureInput) ? signatureInput.join(',') : signatureInput,
    )
    if (!match) return []
    return (match[1].match(/"[^"]*"/g) || []).map((s) => s.slice(1, -1).toLowerCase())
}

/**
 * -11: a body-carrying request to a PS endpoint MUST cover
 * `content-digest` and `content-type`. httpsig verifies the digest itself
 * once the component is covered, so it is the coverage we check here.
 * mock.require_body_signing = false relaxes it for clients that have not
 * cut over yet.
 *
 * @returns a failure tuple, or null when the coverage is acceptable.
 */
export function checkBodySigning(request, sigResult) {
    if (getConfig().require_body_signing === false) return null
    const covered = coveredComponents(
        request.headers['signature-input'],
        sigResult?.label || 'sig',
    )
    const missing = ['content-type', 'content-digest'].filter(
        (c) => !covered.includes(c),
    )
    if (!missing.length) return null
    return fail(
        401,
        'signature_verification_failed',
        `request body signature must cover ${missing.join(' and ')}`,
        {
            'Accept-Signature': ACCEPT_SIG_BODY,
            'Signature-Error': generateSignatureErrorHeader({
                error: 'invalid_input',
                required_input: missing,
            }),
        },
    )
}

export async function verifyRequest(request) {
    const url = new URL(
        request.url,
        `http://${request.headers.host || 'localhost'}`,
    )

    const hasBody = request.method !== 'GET' && request.method !== 'DELETE'

    const sigResult = await httpSigVerify({
        method: request.method,
        authority: url.host,
        path: url.pathname,
        query: url.search ? url.search.slice(1) : '',
        headers: request.headers,
        body: hasBody ? (request.rawBody || '') : undefined,
    })

    if (!sigResult.verified) {
        const noSig =
            !request.headers.signature && !request.headers['signature-input']
        if (noSig) {
            return fail(
                401,
                'signature_required',
                undefined,
                {
                    'Accept-Signature': hasBody ? ACCEPT_SIG_BODY : ACCEPT_SIG_NOBODY,
                    'Accept-Signature-Scheme': ACCEPT_SIG_SCHEME,
                    'Accept-Signature-Alg': ACCEPT_SIG_ALG,
                },
            )
        }
        const headers = {}
        if (sigResult.signatureError) {
            headers['Signature-Error'] = generateSignatureErrorHeader(
                sigResult.signatureError,
            )
        }
        if (sigResult.acceptSignatureAlg) {
            headers['Accept-Signature-Alg'] = generateAcceptSignatureAlgHeader(
                sigResult.acceptSignatureAlg,
            )
        }
        return fail(401, 'signature_verification_failed', sigResult.error, headers)
    }

    if (hasBody) {
        const bodyFailure = checkBodySigning(request, sigResult)
        if (bodyFailure) return bodyFailure
    }

    if (sigResult.keyType !== 'jwt' || !sigResult.jwt) {
        return fail(
            401, 'invalid_key',
            'Signature-Key must use scheme=jwt with an agent_token',
        )
    }

    const { header, payload, raw } = sigResult.jwt

    const verified = await verifyAgentToken(raw, { header, payload })
    if (verified.error) {
        const code = verified.code || 'invalid_jwt'
        return fail(401, code, verified.error, {
            'Signature-Error': generateSignatureErrorHeader({ error: code }),
        })
    }

    return {
        ok: true,
        agent_id: payload.sub,
        agent_iss: payload.iss,
        agent_jkt: sigResult.thumbprint,
        agent_public_key: payload.cnf.jwk,
        agent_payload: payload,
        agent_metadata: verified.metadata,
    }
}

// Fastify helper: calls verifyRequest and either sends the failure response
// or attaches the success info to `request.aauth` and continues.
export async function verifyPreHandler(request, reply) {
    const result = await verifyRequest(request)
    if (!result.ok) {
        for (const [k, v] of Object.entries(result.headers || {})) {
            reply.header(k, v)
        }
        reply
            .code(result.status)
            .header('Content-Type', PROBLEM_CONTENT_TYPE)
            .send(result.body)
        return reply
    }
    request.aauth = result
}
