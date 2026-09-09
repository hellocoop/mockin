// aauth/token.js — POST /aauth/token (PS auth_token_endpoint).
//
// Auto-approve flow (default):
//   1. HTTPSig + agent_token verified by preHandler (request.aauth)
//   2. Verify resource_token from the body, then -11 step 6 (issue #152):
//      the presented_token the agent sent — the person token, or on a
//      step-up the auth token, that it presented to the resource — must
//      verify, and the resource token's presented_jti / ps / sub /
//      mission_s256 / tenant must match it exactly
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
import { verifyPresentedToken } from './verify-presented-token.js'
import { fetchR3Document, autoGrantR3 } from './r3.js'
import { issueAuthToken } from './issue-auth-token.js'
import { parseRequestParameters, canDriveInteraction } from './request-parameters.js'
import { verifyAgentToken } from './verify-agent-token.js'
import { createPending, updatePending } from './state.js'
import { problem } from './problem.js'

const ERROR_STATUS = {
    invalid_request: 400,
    invalid_agent_token: 400,
    expired_agent_token: 400,
    clock_skew: 400,
    invalid_resource_token: 400,
    expired_resource_token: 400,
    invalid_presented_token: 400,
    expired_presented_token: 400,
    revoked_presented_token: 400,
    invalid_scope: 400,
    denied: 403,
    user_unreachable: 403,
    server_error: 500,
}

// /aauth/token is the prefix the two token endpoints sit under, not an
// endpoint itself. A request that lands here is reading a path rather
// than the metadata, so name both URLs in the answer.
export const tokenPrefix = async (req, reply) => {
    return problem(
        reply, 404, 'not_found',
        `/aauth/token is a path prefix, not an endpoint: the auth token endpoint is ${ISSUER}/aauth/token/auth and the person token endpoint is ${ISSUER}/aauth/token/person. Both are published in ${ISSUER}/.well-known/aauth-person.json.`,
    )
}

export const token = async (req, reply) => {
    const cfg = getConfig()
    const aauth = req.aauth // set by verifyPreHandler
    const body = req.body || {}

    // Mock-injected error (skip the rest of the flow)
    const mockErr = mockErrorFor('token')
    if (mockErr) {
        const status = ERROR_STATUS[mockErr] || 400
        return problem(reply, status, mockErr, `Mock error: ${mockErr}`)
    }

    if (!body.resource_token) {
        return problem(reply, 400, 'invalid_request', 'missing resource_token')
    }
    // -11 issue #152: REQUIRED — the token the agent presented to the
    // resource, whose jti the resource token's presented_jti names.
    if (typeof body.presented_token !== 'string' || !body.presented_token) {
        return problem(
            reply, 400, 'invalid_request',
            'missing presented_token: the person token (or, on a step-up, the auth token) presented to the resource, named by the resource token presented_jti',
        )
    }

    // upstream_token is call chaining — deferred fleet-wide, not implemented.
    if (body.upstream_token !== undefined) {
        return problem(
            reply, 400, 'invalid_request',
            'upstream_token is not supported: call chaining is not implemented by mockin',
        )
    }

    // justification, login_hint, tenant, domain_hint, prompt, platform,
    // device, capabilities — parsed once, shared with the person endpoint.
    const parsed = parseRequestParameters(body)
    if (parsed.error) {
        return problem(reply, 400, 'invalid_request', parsed.error)
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
            return problem(
                reply, 400, 'invalid_request', 'subagent_token must be a string',
            )
        }
        const sub = await verifyAgentToken(body.subagent_token)
        if (sub.error) {
            return problem(
                reply, 400, sub.code || 'invalid_agent_token',
                `subagent_token: ${sub.error}`,
            )
        }
        if (sub.payload.parent_agent !== aauth.agent_id) {
            return problem(
                reply, 400, 'invalid_agent_token',
                `subagent_token parent_agent "${sub.payload.parent_agent}" does not name the signing agent "${aauth.agent_id}"`,
            )
        }
        cnfJwk = sub.payload.cnf.jwk
        expectedJkt = await calculateJwkThumbprint(cnfJwk)
    }

    const rt = await verifyResourceToken(body.resource_token, expectedJkt)
    if (rt.error) {
        return problem(
            reply, 400,
            rt.expired ? 'expired_resource_token' : 'invalid_resource_token',
            rt.error,
        )
    }
    // Step 6: the presented token against the resource token.
    const presented = await verifyPresentedToken(body.presented_token, rt)
    if (presented.error) {
        return problem(reply, ERROR_STATUS[presented.code] || 400, presented.code, presented.error)
    }

    // ── The connection ceremony ───────────────────────────────────────
    // A connection-only resource token asks for no token at all: the person
    // has to link an upstream account at the resource. The PS holds a pending
    // record, sends the person to the resource's own interaction_endpoint with
    // the code the resource is holding, and the ceremony ends when the resource
    // bounces the browser back — `connection_established`, no auth token.
    if (rt.connection_only) {
        if (!canDriveInteraction(params, { requireDeclared: cfg.require_capabilities })) {
            return problem(
                reply, 403, 'user_unreachable',
                'a connection requires user interaction and the agent did not declare the interaction capability',
            )
        }
        const interactionEndpoint = rt.resource_metadata?.interaction_endpoint
        if (typeof interactionEndpoint !== 'string' || !interactionEndpoint) {
            return problem(
                reply, 400, 'invalid_resource_token',
                `resource ${rt.resource_url} publishes no interaction_endpoint, so its connection code cannot be delivered`,
            )
        }
        if (new URL(interactionEndpoint).protocol !== 'https:') {
            return problem(
                reply, 400, 'invalid_resource_token',
                `resource interaction_endpoint must be https, got ${interactionEndpoint}`,
            )
        }
        const { id, code } = createPending({
            kind: 'connection',
            agent_id: aauth.agent_id,
            resource_url: rt.resource_url,
            interaction_endpoint: interactionEndpoint,
            interaction_code: rt.interaction_code,
            account: rt.account || null,
            requirement: 'interaction',
            params,
        })
        const location = `${ISSUER}/aauth/pending/${id}`
        reply.code(202)
        reply.header('Location', location)
        reply.header('Retry-After', '0')
        reply.header('Cache-Control', 'no-store')
        reply.header('AAuth-Requirement', `requirement=interaction; code="${code}"`)
        return reply.send({ status: 'pending', location })
    }

    let r3 = null
    if (rt.r3) {
        const fetched = await fetchR3Document({
            r3_uri: rt.r3.uri,
            expected_s256: rt.r3.s256,
        })
        if (fetched instanceof Error) {
            return problem(
                reply, 400, 'invalid_resource_token',
                `r3 fetch failed: ${fetched.message}`,
            )
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
        // §Auth Token Structure: never past the presented token's exp.
        presented_exp: presented.exp,
        r3,
    }

    // Deferred response
    if (cfg.requirement) {
        // Same gate as the person token endpoint: an agent that declared
        // capabilities without `interaction` cannot complete one.
        if (
            cfg.requirement === 'interaction' &&
            !canDriveInteraction(params, { requireDeclared: cfg.require_capabilities })
        ) {
            return problem(
                reply, 403, 'user_unreachable',
                'user interaction is required and the agent did not declare the interaction capability',
            )
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
