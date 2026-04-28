// aauth/verify-request.js — HTTPSig + agent_token verification.
//
// Every agent-facing AAuth endpoint runs the incoming request through this:
//
//   1. RFC9421 signature verification (Signature-Input + Signature)
//   2. The Signature-Key MUST use scheme=jwt and present an aa-agent+jwt
//   3. The agent_token's signature MUST verify against its issuer's JWKS
//   4. Header/claim sanity (typ, iss, exp, cnf.jwk presence)
//
// On failure the helper returns a tuple describing the response so the
// handler can `return reply.code(...).headers(...).send(...)`. On success
// it returns identity/key material derived from the verified JWT.

import * as jose from 'jose'
import {
    verify as httpSigVerify,
    generateSignatureErrorHeader,
    generateAcceptSignatureHeader,
} from '@hellocoop/httpsig'

import { getEntity, AGENT_DWK } from './entity-cache.js'

const ACCEPT_SIG_BODY = generateAcceptSignatureHeader({
    label: 'sig',
    components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
    sigkey: 'jkt',
})

const ACCEPT_SIG_NOBODY = generateAcceptSignatureHeader({
    label: 'sig',
    components: ['@method', '@authority', '@path', 'signature-key'],
    sigkey: 'jkt',
})

function fail(status, body, headers = {}) {
    return { ok: false, status, body, headers }
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
                { error: 'signature_required' },
                { 'Accept-Signature': hasBody ? ACCEPT_SIG_BODY : ACCEPT_SIG_NOBODY },
            )
        }
        const headers = {}
        if (sigResult.signatureError) {
            headers['Signature-Error'] = generateSignatureErrorHeader(
                sigResult.signatureError,
            )
        }
        return fail(
            401,
            {
                error: 'signature_verification_failed',
                error_description: sigResult.error,
            },
            headers,
        )
    }

    if (sigResult.keyType !== 'jwt' || !sigResult.jwt) {
        return fail(401, {
            error: 'invalid_key',
            error_description: 'Signature-Key must use scheme=jwt with an agent_token',
        })
    }

    const { header, payload, raw } = sigResult.jwt

    if (header.typ !== 'aa-agent+jwt') {
        return fail(401, {
            error: 'invalid_jwt',
            error_description: `expected aa-agent+jwt, got ${header.typ}`,
        })
    }

    const agentIss = payload.iss
    if (!agentIss) {
        return fail(401, {
            error: 'invalid_jwt',
            error_description: 'agent_token missing iss',
        })
    }
    const dwk = payload.dwk || AGENT_DWK

    let entity
    try {
        entity = await getEntity(agentIss, dwk)
    } catch (err) {
        return fail(401, {
            error: 'invalid_jwt',
            error_description: `agent server discovery failed: ${err.message}`,
        })
    }

    try {
        await jose.jwtVerify(raw, jose.createLocalJWKSet(entity.jwks))
    } catch (err) {
        return fail(401, {
            error: 'invalid_jwt',
            error_description: `agent_token signature: ${err.message}`,
        })
    }

    if (!payload.sub) {
        return fail(401, {
            error: 'invalid_jwt',
            error_description: 'agent_token missing sub',
        })
    }
    if (!payload.cnf?.jwk) {
        return fail(401, {
            error: 'invalid_jwt',
            error_description: 'agent_token missing cnf.jwk',
        })
    }

    return {
        ok: true,
        agent_id: payload.sub,
        agent_iss: agentIss,
        agent_jkt: sigResult.thumbprint,
        agent_public_key: payload.cnf.jwk,
        agent_payload: payload,
        agent_metadata: entity.metadata,
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
        reply.code(result.status).send(result.body)
        return reply
    }
    request.aauth = result
}
