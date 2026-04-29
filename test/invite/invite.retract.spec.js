import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

async function createInvitation() {
    const res = await fastify.inject({
        method: 'POST',
        url: '/invite',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({
            email: 'invitee@example.com',
            prompt: 'Join',
            client_id: 'c1',
        }),
    })
    return res.json().invite
}

describe('Invite — DELETE /invite/:id retract', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('retracts an existing invitation', async function () {
        const inv = await createInvitation()
        const res = await fastify.inject({
            method: 'DELETE',
            url: `/invite/${inv.id}`,
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().success).to.equal(true)
    })

    it('subsequent GET /invitation/:id reports invitation_not_found', async function () {
        const inv = await createInvitation()
        await fastify.inject({
            method: 'DELETE',
            url: `/invite/${inv.id}`,
        })
        const res = await fastify.inject({
            method: 'GET',
            url: `/invitation/${inv.id}`,
        })
        expect(res.json().error).to.equal('invitation_not_found')
    })

    it('404 when retracting unknown id', async function () {
        const res = await fastify.inject({
            method: 'DELETE',
            url: '/invite/inv_unknown',
        })
        expect(res.statusCode).to.equal(404)
    })

    it('honours mock error_endpoint=retract', async function () {
        const inv = await createInvitation()
        await fastify.inject({
            method: 'PUT',
            url: '/mock/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                error: 'access_denied',
                error_endpoint: 'retract',
            }),
        })
        const res = await fastify.inject({
            method: 'DELETE',
            url: `/invite/${inv.id}`,
        })
        expect(res.statusCode).to.equal(400)
        expect(res.json().error).to.equal('access_denied')
    })
})
