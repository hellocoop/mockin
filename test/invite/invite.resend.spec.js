import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

describe('Invite — PUT /invite/:id resend', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('updates lastEmailedAt without changing other fields', async function () {
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
        const created = inv.lastEmailedAt
        await new Promise((r) => setTimeout(r, 1050))

        const res = await fastify.inject({
            method: 'PUT',
            url: `/invite/${inv.id}`,
        })
        expect(res.statusCode).to.equal(200)
        const after = res.json().invite
        expect(after.lastEmailedAt).to.be.greaterThan(created)
        expect(after.id).to.equal(inv.id)
        expect(after.invitee).to.equal(inv.invitee)
        expect(after.prompt).to.equal(inv.prompt)
        expect(after.expiresAt).to.equal(inv.expiresAt)
    })

    it('404 when resending unknown id', async function () {
        const res = await fastify.inject({
            method: 'PUT',
            url: '/invite/inv_unknown',
        })
        expect(res.statusCode).to.equal(404)
    })
})
