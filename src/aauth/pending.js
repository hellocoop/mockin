// aauth/pending.js — /aauth/pending/:id (poll, clarify, cancel).
//
// Two signing modes are accepted depending on the entry kind:
//   - bootstrap: HWK (ephemeral key, no agent_token yet)
//   - all other kinds: JWT (agent_token in Signature-Key)
//
// Verification therefore runs inside the handler — after we look up the
// entry — rather than in a generic preHandler.

import * as jose from 'jose'
import { calculateJwkThumbprint } from 'jose'
import {
    verify as httpSigVerify,
    generateSignatureErrorHeader,
    generateAcceptSignatureHeader,
} from '@hellocoop/httpsig'

import { ISSUER } from '../config.js'
import { getPending, updatePending, deletePending } from './state.js'
import { issueAuthToken } from './issue-auth-token.js'
import { issueBootstrapToken } from './bootstrap.js'
import { getEntity, AGENT_DWK } from './entity-cache.js'

const ACCEPT_SIG_GET = generateAcceptSignatureHeader({
    label: 'sig',
    components: ['@method', '@authority', '@path', 'signature-key'],
    sigkey: 'jkt',
})

async function runHttpSig(request) {
    const url = new URL(
        request.url,
        `http://${request.headers.host || 'localhost'}`,
    )
    const hasBody = request.method !== 'GET' && request.method !== 'DELETE'
    return httpSigVerify({
        method: request.method,
        authority: url.host,
        path: url.pathname,
        query: url.search ? url.search.slice(1) : '',
        headers: request.headers,
        body: hasBody ? (request.rawBody || '') : undefined,
    })
}

function noSig(reply) {
    reply.code(401).header('Accept-Signature', ACCEPT_SIG_GET).send({
        error: 'signature_required',
    })
}

async function verifyForEntry(request, reply, entry) {
    const sigResult = await runHttpSig(request)
    if (!sigResult.verified) {
        const noSigPresent =
            !request.headers.signature && !request.headers['signature-input']
        if (noSigPresent) return noSig(reply)
        if (sigResult.signatureError) {
            reply.header(
                'Signature-Error',
                generateSignatureErrorHeader(sigResult.signatureError),
            )
        }
        return reply.code(401).send({
            error: 'signature_verification_failed',
            error_description: sigResult.error,
        })
    }

    if (entry.kind === 'bootstrap') {
        if (sigResult.keyType !== 'hwk') {
            return reply.code(401).send({
                error: 'invalid_key',
                error_description: 'bootstrap polling requires hwk scheme',
            })
        }
        const expectedJkt = await calculateJwkThumbprint(entry.ephemeral_jwk)
        if (sigResult.thumbprint !== expectedJkt) {
            return reply.code(401).send({
                error: 'invalid_key',
                error_description: 'hwk key does not match bootstrap binding',
            })
        }
        return null // ok
    }

    // Non-bootstrap entries require an agent_token (JWT scheme).
    if (sigResult.keyType !== 'jwt' || !sigResult.jwt) {
        return reply.code(401).send({
            error: 'invalid_key',
            error_description: 'expected sig=jwt with agent_token',
        })
    }
    const { header, payload, raw } = sigResult.jwt
    if (header.typ !== 'aa-agent+jwt') {
        return reply.code(401).send({
            error: 'invalid_jwt',
            error_description: `expected aa-agent+jwt, got ${header.typ}`,
        })
    }
    if (!payload.iss) {
        return reply.code(401).send({
            error: 'invalid_jwt',
            error_description: 'agent_token missing iss',
        })
    }
    let entity
    try {
        entity = await getEntity(payload.iss, payload.dwk || AGENT_DWK)
    } catch (err) {
        return reply.code(401).send({
            error: 'invalid_jwt',
            error_description: `agent server discovery failed: ${err.message}`,
        })
    }
    try {
        await jose.jwtVerify(raw, jose.createLocalJWKSet(entity.jwks))
    } catch (err) {
        return reply.code(401).send({
            error: 'invalid_jwt',
            error_description: `agent_token signature: ${err.message}`,
        })
    }
    return null // ok
}

export const pendingGet = async (req, reply) => {
    const entry = getPending(req.params.id)
    if (!entry) return reply.code(404).send({ error: 'not_found' })

    const verifyErr = await verifyForEntry(req, reply, entry)
    if (verifyErr) return verifyErr

    if (entry.status === 'cancelled') {
        return reply.code(410).send({ error: 'cancelled' })
    }
    if (entry.status === 'error') {
        return reply
            .code(403)
            .send({ error: entry.error || 'denied' })
    }

    if (entry.status === 'pending') {
        // Clarification: client must POST a clarification_response first.
        if (entry.requirement === 'clarification') {
            const location = `${ISSUER}/aauth/pending/${entry.id}`
            reply.code(202)
            reply.header('Location', location)
            reply.header('Retry-After', '5')
            reply.header('Cache-Control', 'no-store')
            return reply.send({
                status: 'pending',
                location,
                clarification: entry.clarification ||
                    'Why do you need access to this resource?',
                timeout: 120,
            })
        }
        // Bootstrap polls before consent — keep them pending.
        if (entry.kind === 'bootstrap' && !entry.preApprove) {
            const location = `${ISSUER}/aauth/pending/${entry.id}`
            reply.code(202)
            reply.header('Location', location)
            reply.header('Retry-After', '5')
            reply.header('Cache-Control', 'no-store')
            return reply.send({ status: 'pending', location })
        }
        // Default auto-resolve path for token / approval / interaction.
        updatePending(entry.id, { status: 'approved' })
    }

    if (entry.kind === 'token') {
        const issued = await issueAuthToken({
            agent_id: entry.agent_id,
            agent_public_key: entry.agent_public_key,
            resource_url: entry.resource_url,
            scope: entry.scope,
            r3: entry.r3,
        })
        deletePending(entry.id)
        return reply.code(200).send(issued)
    }

    if (entry.kind === 'bootstrap') {
        const issued = await issueBootstrapToken({
            agent_server: entry.agent_server,
            ephemeral_jwk: entry.ephemeral_jwk,
        })
        deletePending(entry.id)
        return reply.code(200).send(issued)
    }

    if (entry.kind === 'permission') {
        deletePending(entry.id)
        return reply.code(200).send({ permission: 'granted' })
    }
    if (entry.kind === 'interaction') {
        deletePending(entry.id)
        return reply.code(200).send({ status: 'completed' })
    }

    return reply.code(500).send({ error: 'server_error' })
}

export const pendingPost = async (req, reply) => {
    const entry = getPending(req.params.id)
    if (!entry) return reply.code(404).send({ error: 'not_found' })

    const verifyErr = await verifyForEntry(req, reply, entry)
    if (verifyErr) return verifyErr

    const body = req.body || {}

    if (typeof body.clarification_response === 'string') {
        updatePending(entry.id, {
            status: 'pending',
            requirement: null,
            clarifications: [
                ...(entry.clarifications || []),
                body.clarification_response,
            ],
        })
        return reply.code(202).send({ status: 'pending' })
    }

    if (typeof body.resource_token === 'string') {
        updatePending(entry.id, {
            status: 'pending',
            requirement: null,
            updated_resource_token: body.resource_token,
        })
        return reply.code(202).send({ status: 'pending' })
    }

    return reply.code(400).send({
        error: 'invalid_request',
        error_description: 'expected clarification_response or resource_token',
    })
}

export const pendingDelete = async (req, reply) => {
    const entry = getPending(req.params.id)
    if (!entry) return reply.code(404).send({ error: 'not_found' })
    const verifyErr = await verifyForEntry(req, reply, entry)
    if (verifyErr) return verifyErr
    updatePending(entry.id, { status: 'cancelled' })
    return reply.code(204).send()
}
