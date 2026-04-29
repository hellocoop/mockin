import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

describe('Invite — POST /invitation/:id/report (abuse)', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('reports abuse and removes the invitation', async function () {
        const create = await fastify.inject({
            method: 'POST',
            url: '/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                email: 'invitee@example.com',
                prompt: 'Join',
                client_id: 'c1',
            }),
        })
        const inv = create.json().invite

        const res = await fastify.inject({
            method: 'POST',
            url: `/invitation/${inv.id}/report`,
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().success).to.equal(true)

        // Subsequent fetch reports invitation_not_found
        const after = await fastify.inject({
            method: 'GET',
            url: `/invitation/${inv.id}`,
        })
        expect(after.json().error).to.equal('invitation_not_found')
    })

    it('400 on unknown id', async function () {
        const res = await fastify.inject({
            method: 'POST',
            url: '/invitation/inv_doesnotexist/report',
        })
        expect(res.statusCode).to.equal(400)
        expect(res.json().error).to.equal('invitation_not_found')
    })
})
