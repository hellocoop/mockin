// aauth/permission.js — POST /aauth/permission.
//
// Per spec the agent asks the PS to permit a non-resource action (e.g.
// SendEmail). Mockin auto-grants by default; mock.permission='denied'
// flips to a refusal with reason.

import { getConfig } from './mock.js'
import { problem } from './problem.js'

export const permission = async (req, reply) => {
    const cfg = getConfig()
    const body = req.body || {}

    if (!body.action || typeof body.action !== 'string') {
        return problem(reply, 400, 'invalid_request', 'missing action')
    }

    if (cfg.permission === 'denied') {
        return reply.code(200).send({
            permission: 'denied',
            reason: cfg.permission_reason || 'Mock denial',
        })
    }

    return reply.code(200).send({ permission: 'granted' })
}
