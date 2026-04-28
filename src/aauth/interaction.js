// aauth/interaction.js — POST /aauth/interaction.
//
// Agent reaches the user via the PS. Mockin handles each `type` with
// canned auto-completion.

import { ISSUER } from '../config.js'
import { createPending } from './state.js'

const VALID_TYPES = new Set(['interaction', 'payment', 'question', 'completion'])

export const interaction = async (req, reply) => {
    const aauth = req.aauth
    const body = req.body || {}

    if (!body.type || !VALID_TYPES.has(body.type)) {
        return reply.code(400).send({
            error: 'invalid_request',
            error_description: 'type must be interaction|payment|question|completion',
        })
    }

    if (body.type === 'completion') {
        return reply.code(200).send({ status: 'received' })
    }

    if (body.type === 'question') {
        return reply.code(200).send({
            answer: 'Mock answer: yes, proceed.',
        })
    }

    // interaction / payment — defer briefly via pending so polling code-paths
    // exist for client testing.
    const { id } = createPending({
        kind: 'interaction',
        agent_id: aauth.agent_id,
        type: body.type,
        url: body.url || null,
        code: body.code || null,
    })
    const location = `${ISSUER}/aauth/pending/${id}`
    reply.code(202)
    reply.header('Location', location)
    reply.header('Retry-After', '0')
    reply.header('Cache-Control', 'no-store')
    reply.header('AAuth-Requirement', 'requirement=approval')
    return reply.send({ status: 'pending', location })
}
