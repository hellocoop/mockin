// aauth/token.js — POST /aauth/token (PS auth_token_endpoint).
//
// Auto-approve flow (default):
//   1. HTTPSig + agent_token verified by preHandler (request.aauth)
//   2. Verify resource_token from the body, including -11 step 6: the
//      person token named by `person_token_jti` must be one this PS
//      issued, with matching ps / sub / mission_s256 / tenant
//   3. If R3, fetch + hash-verify the document
//   4. Inject mock errors / deferred response if configured
//   5. Issue auth_token immediately, 200
//
// Deferred flow (mock.requirement set):
//   - Create a pending entry with an interaction code
//   - Return 202 + AAuth-Requirement header + Location
//   - Agent polls /aauth/pending/:id; first poll resolves and returns token

import { calculateJwkThumbprint } from 'jose'

import { ISSUER } from '../config.js'
import { getConfig, mockErrorFor } from './mock.js'
import { verifyResourceToken } from './verify-resource-token.js'
import { fetchR3Document, autoGrantR3 } from './r3.js'
import { issueAuthToken } from './issue-auth-token.js'
import { parseRequestParameters, canDriveInteraction } from './request-parameters.js'
import { verifyAgentToken } from './verify-agent-token.js'
import { createPending, updatePending } from './state.js'

const ERROR_STATUS = {
    invalid_request: 400,
    invalid_agent_token: 400,
    expired_agent_token: 400,
    invalid_resource_token: 400,
    expired_resource_token: 400,
    invalid_scope: 400,
    denied: 403,
    user_unreachable: 403,
    server_error: 500,
}

export const token = async (req, reply) => {
    const cfg = getConfig()
    const aauth = req.aauth // set by verifyPreHandler
    const body = req.body || {}

    // Mock-injected error (skip the rest of the flow)
    const mockErr = mockErrorFor('token')
    if (mockErr) {
        const status = ERROR_STATUS[mockErr] || 400
        return reply.code(status).send({
            error: mockErr,
            error_description: `Mock error: ${mockErr}`,
        })
    }

    if (!body.resource_token) {
        return reply.code(400).send({
            error: 'invalid_request',
            error_description: 'missing resource_token',
        })
    }

    // upstream_token is call chaining — deferred fleet-wide, not implemented.
    if (body.upstream_token !== undefined) {
        return reply.code(400).send({
            error: 'invalid_request',
            error_description:
                'upstream_token is not supported: call chaining is not implemented by mockin',
        })
    }

    // justification, login_hint, tenant, domain_hint, prompt, platform,
    // device, capabilities — parsed once, shared with the person endpoint.
    const parsed = parseRequestParameters(body)
    if (parsed.error) {
        return reply.code(400).send({
            error: 'invalid_request',
            error_description: parsed.error,
        })
    }
    const params = parsed.params

    // Parent-mediated sub-agent authorization (interop surface 5): the
    // parent signs the request, so §Resource Token Verification step 5
    // compares agent_jkt against the SUB-agent's cnf.jwk instead, and the
    // issued auth token binds the sub-agent's key.
    let expectedJkt = aauth.agent_jkt
    let cnfJwk = aauth.agent_public_key
    if (body.subagent_token !== undefined) {
        if (typeof body.subagent_token !== 'string') {
            return reply.code(400).send({
                error: 'invalid_request',
                error_description: 'subagent_token must be a string',
            })
        }
        const sub = await verifyAgentToken(body.subagent_token)
        if (sub.error) {
            return reply.code(400).send({
                error: 'invalid_agent_token',
                error_description: `subagent_token: ${sub.error}`,
            })
        }
        if (sub.payload.parent_agent !== aauth.agent_id) {
            return reply.code(400).send({
                error: 'invalid_agent_token',
                error_description:
                    `subagent_token parent_agent "${sub.payload.parent_agent}" does not name the signing agent "${aauth.agent_id}"`,
            })
        }
        cnfJwk = sub.payload.cnf.jwk
        expectedJkt = await calculateJwkThumbprint(cnfJwk)
    }

    const rt = await verifyResourceToken(body.resource_token, expectedJkt)
    if (rt.error) {
        return reply.code(400).send({
            error: rt.expired ? 'expired_resource_token' : 'invalid_resource_token',
            error_description: rt.error,
        })
    }

    let r3 = null
    if (rt.r3) {
        const fetched = await fetchR3Document({
            r3_uri: rt.r3.uri,
            expected_s256: rt.r3.s256,
        })
        if (fetched instanceof Error) {
            return reply.code(400).send({
                error: 'invalid_resource_token',
                error_description: `r3 fetch failed: ${fetched.message}`,
            })
        }
        const grants = autoGrantR3({ document: fetched.document })
        r3 = { uri: rt.r3.uri, s256: rt.r3.s256, ...grants }
    }

    const issueArgs = {
        agent_public_key: cnfJwk,
        resource_url: rt.resource_url,
        scope: rt.scope,
        sub: rt.sub,
        mission_s256: rt.mission_s256 || undefined,
        tenant: rt.tenant || undefined,
        account: rt.account || undefined,
        r3,
    }

    // Deferred response
    if (cfg.requirement) {
        // Same gate as the person token endpoint: an agent that declared
        // capabilities without `interaction` cannot complete one.
        if (cfg.requirement === 'interaction' && !canDriveInteraction(params)) {
            return reply.code(403).send({
                error: 'user_unreachable',
                error_description:
                    'user interaction is required and the agent did not declare the interaction capability',
            })
        }
        const { id, code } = createPending({
            kind: 'token',
            agent_id: aauth.agent_id,
            issueArgs,
            requirement: cfg.requirement,
            justification: params.justification || null,
            params,
        })
        // auto_approve (the default) short-circuits the interaction so the
        // first poll returns the token. Set it false to make a test drive
        // it: poll → 202, GET /aauth/consent?code=… , poll → 200.
        // Clarification is unaffected — it waits for the agent's answer.
        if (cfg.auto_approve && cfg.requirement === 'interaction') {
            updatePending(id, { status: 'approved' })
        }
        const location = `${ISSUER}/aauth/pending/${id}`
        reply.code(202)
        reply.header('Location', location)
        reply.header('Retry-After', '0')
        reply.header('Cache-Control', 'no-store')

        if (cfg.requirement === 'interaction') {
            const interactionUrl = `${ISSUER}/aauth/consent`
            reply.header(
                'AAuth-Requirement',
                `requirement=interaction; url="${interactionUrl}"; code="${code}"`,
            )
            return reply.send({ status: 'pending', location })
        }
        if (cfg.requirement === 'clarification') {
            reply.header('AAuth-Requirement', 'requirement=clarification')
            return reply.send({
                status: 'pending',
                location,
                clarification:
                    cfg.clarification ||
                    'Why do you need access to this resource?',
                timeout: 120,
            })
        }
        // approval
        reply.header('AAuth-Requirement', 'requirement=approval')
        return reply.send({ status: 'pending', location })
    }

    const issued = await issueAuthToken(issueArgs)
    reply.header('Cache-Control', 'no-store')
    return reply.code(200).send(issued)
}
