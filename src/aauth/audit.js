// aauth/audit.js — POST /aauth/audit.
//
// Fire-and-forget log endpoint. Mockin acknowledges with 201 and discards.

import { problem } from './problem.js'

export const audit = async (req, reply) => {
    const body = req.body || {}
    if (!body.action || typeof body.action !== 'string') {
        return problem(reply, 400, 'invalid_request', 'missing action')
    }
    if (!body.mission || typeof body.mission !== 'object') {
        return problem(reply, 400, 'invalid_request', 'missing mission')
    }
    return reply.code(201).send()
}
