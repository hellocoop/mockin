// aauth/token.js — POST /aauth/token (PS token endpoint).
//
// Auto-approve flow (default):
//   1. HTTPSig + agent_token verified by preHandler (request.aauth)
//   2. Verify resource_token from request body
//   3. If R3, fetch + hash-verify the document
//   4. Inject mock errors / deferred response if configured
//   5. Issue auth_token immediately, 200
//
// Deferred flow (mock.requirement set):
//   - Create a pending entry with an interaction code
//   - Return 202 + AAuth-Requirement header + Location
//   - Agent polls /aauth/pending/:id; first poll resolves and returns token

import { ISSUER } from '../config.js'
import { getConfig, mockErrorFor } from './mock.js'
import { verifyResourceToken } from './verify-resource-token.js'
import { fetchR3Document, autoGrantR3 } from './r3.js'
import { issueAuthToken } from './issue-auth-token.js'
import { createPending } from './state.js'

const ERROR_STATUS = {
    invalid_request: 400,
    invalid_resource_token: 400,
    invalid_scope: 400,
    user_unreachable: 400,
    denied: 403,
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

    const rt = await verifyResourceToken(
        body.resource_token,
        aauth.agent_id,
        aauth.agent_jkt,
    )
    if (rt.error) {
        return reply.code(400).send({
            error: 'invalid_resource_token',
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

    // Deferred response
    if (cfg.requirement) {
        const { id, code } = createPending({
            kind: 'token',
            agent_id: aauth.agent_id,
            agent_public_key: aauth.agent_public_key,
            resource_url: rt.resource_url,
            scope: rt.scope,
            r3,
            requirement: cfg.requirement,
            justification: body.justification || null,
        })
        const location = `${ISSUER}/aauth/pending/${id}`
        reply.code(202)
        reply.header('Location', location)
        reply.header('Retry-After', '0')
        reply.header('Cache-Control', 'no-store')

        if (cfg.requirement === 'interaction') {
            const interactionUrl = `${ISSUER}/aauth/interaction-ui`
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

    const issued = await issueAuthToken({
        agent_id: aauth.agent_id,
        agent_public_key: aauth.agent_public_key,
        resource_url: rt.resource_url,
        scope: rt.scope,
        r3,
    })
    return reply.code(200).send(issued)
}
