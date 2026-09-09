// aauth/person.js — POST /aauth/person (PS person_token_endpoint).
//
// Protocol -11 §Person Token Endpoint. Signed POST; the agent presents its
// agent token via `Signature-Key: sig=jwt;jwt="…"` (verified by the
// preHandler, which also enforces content-digest + content-type coverage).
//
// Request body:
//   resource        REQUIRED — the resource the token is for; becomes `aud`
//   mission_s256    OPTIONAL — stamped on the issued token
//   subagent_token  OPTIONAL — a sub-agent's agent token; the issued token's
//                   `cnf` is the sub-agent's key (§Sub-Agents, interop
//                   surface 5)
//   upstream_token  OPTIONAL in the spec — NOT implemented; call chaining is
//                   deferred fleet-wide, and mockin rejects rather than
//                   silently ignoring it
//
// Auto-approve (default): 200 { person_token, expires_in }.
// Deferred (mock.person_requirement): 202 + Location + Retry-After +
// AAuth-Requirement, resolved by polling /aauth/pending/:id.

import { ISSUER } from '../config.js'
import { getConfig, mockErrorFor } from './mock.js'
import { issuePersonToken } from './issue-person-token.js'
import { verifyAgentToken } from './verify-agent-token.js'
import { parseRequestParameters, canDriveInteraction } from './request-parameters.js'
import { createPending, updatePending } from './state.js'
import { problem } from './problem.js'

const ERROR_STATUS = {
    invalid_request: 400,
    invalid_agent_token: 400,
    expired_agent_token: 400,
    clock_skew: 400,
    denied: 403,
    user_unreachable: 403,
    server_error: 500,
}

// §Server Identifiers: https, host only, lowercase, no port/path/query/
// fragment, no trailing slash. Mockin is a local mock, so http on a
// loopback host (with a port) is also accepted — otherwise nothing running
// on 127.0.0.1 could be named as a resource.
export function validateResourceIdentifier(value) {
    if (typeof value !== 'string' || !value) return 'resource is required'
    let url
    try {
        url = new URL(value)
    } catch {
        return `resource "${value}" is not an absolute URL`
    }
    const loopback = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
        return `resource "${value}" must use the https scheme`
    }
    if (url.search) return `resource "${value}" must not contain a query`
    if (url.hash) return `resource "${value}" must not contain a fragment`
    if (url.pathname !== '/' || value.endsWith('/')) {
        return `resource "${value}" must contain only scheme and host, with no trailing slash`
    }
    if (url.port && !loopback) return `resource "${value}" must not contain a port`
    if (value !== value.toLowerCase()) return `resource "${value}" must be lowercase`
    return null
}

export const person = async (req, reply) => {
    const cfg = getConfig()
    const aauth = req.aauth // set by verifyPreHandler
    const body = req.body || {}

    const mockErr = mockErrorFor('person')
    if (mockErr) {
        return problem(
            reply, ERROR_STATUS[mockErr] || 400, mockErr,
            `Mock error: ${mockErr}`,
        )
    }

    const resourceError = validateResourceIdentifier(body.resource)
    if (resourceError) {
        return problem(reply, 400, 'invalid_request', resourceError)
    }

    if (body.upstream_token !== undefined) {
        return problem(
            reply, 400, 'invalid_request',
            'upstream_token is not supported: call chaining is not implemented by mockin',
        )
    }

    if (body.mission_s256 !== undefined && typeof body.mission_s256 !== 'string') {
        return problem(reply, 400, 'invalid_request', 'mission_s256 must be a string')
    }
    // mission_endpoint is unimplemented, so there is no mission to look up.
    // The value is accepted, stamped on the token, and later compared
    // against the resource token — which is what the fleet tests.

    // The consent-flow parameters, the same set the auth token endpoint
    // takes: justification, login_hint, tenant, domain_hint, prompt,
    // platform, device, capabilities.
    const parsed = parseRequestParameters(body)
    if (parsed.error) {
        return problem(reply, 400, 'invalid_request', parsed.error)
    }
    const params = parsed.params

    // The token binds the requesting agent's key, unless a subagent_token
    // names one — then it binds the sub-agent's, and the parent must be
    // named by the sub-agent token's `parent_agent`.
    let cnfJwk = aauth.agent_public_key
    let subject_agent_exp = aauth.agent_payload?.exp

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
        subject_agent_exp = Math.min(
            subject_agent_exp ?? Infinity,
            sub.payload.exp ?? Infinity,
        )
    }

    const issueArgs = {
        agent_public_key: cnfJwk,
        resource: body.resource,
        lifetime: cfg.token_lifetime || undefined,
        agent_token_exp: subject_agent_exp,
        mission_s256: body.mission_s256,
        // The agent names the tenant: nothing else selects which of a
        // person's contexts — personal, or one of several managed — the
        // issued token carries (AAuth issue #88).
        tenant: params.tenant || cfg.tenant || undefined,
    }

    // Deferred consent path — the one the fleet cannot exercise anywhere
    // else. mock.person_requirement selects it.
    if (cfg.person_requirement) {
        // An agent that declared its capabilities without `interaction`
        // cannot drive the url + code we would hand it, so a 202 would be
        // unsatisfiable. Terminal, per §Token Endpoint Error Codes.
        if (
            cfg.person_requirement === 'interaction' &&
            !canDriveInteraction(params, { requireDeclared: cfg.require_capabilities })
        ) {
            return problem(
                reply, 403, 'user_unreachable',
                'user interaction is required and the agent did not declare the interaction capability',
            )
        }
        const { id, code } = createPending({
            kind: 'person',
            agent_id: aauth.agent_id,
            issueArgs,
            requirement: cfg.person_requirement,
            // Recorded for the consent display and the connected-agents
            // entry a real PS would create here.
            params,
        })
        // auto_approve (the default) short-circuits the interaction so the
        // first poll returns the token. Set it false to make a test drive
        // it: poll → 202, GET /aauth/consent?code=… , poll → 200.
        if (cfg.auto_approve && cfg.person_requirement === 'interaction') {
            updatePending(id, { status: 'approved' })
        }
        const location = `${ISSUER}/aauth/pending/${id}`
        reply.code(202)
        reply.header('Location', location)
        reply.header('Retry-After', '0')
        reply.header('Cache-Control', 'no-store')

        if (cfg.person_requirement === 'interaction') {
            const interactionUrl = `${ISSUER}/aauth/consent`
            reply.header(
                'AAuth-Requirement',
                `requirement=interaction; url="${interactionUrl}"; code="${code}"`,
            )
            return reply.send({
                status: 'pending',
                location,
                requirement: 'interaction',
                code,
            })
        }
        reply.header('AAuth-Requirement', `requirement=${cfg.person_requirement}`)
        return reply.send({ status: 'pending', location })
    }

    const issued = await issuePersonToken(issueArgs)
    reply.header('Cache-Control', 'no-store')
    return reply.code(200).send(issued)
}
