// aauth/audit.js — POST /aauth/audit.
//
// Fire-and-forget log endpoint. Mockin acknowledges with 201 and discards.

export const audit = async (req, reply) => {
    const body = req.body || {}
    if (!body.action || typeof body.action !== 'string') {
        return reply.code(400).send({
            error: 'invalid_request',
            error_description: 'missing action',
        })
    }
    if (!body.mission || typeof body.mission !== 'object') {
        return reply.code(400).send({
            error: 'invalid_request',
            error_description: 'missing mission',
        })
    }
    return reply.code(201).send()
}
