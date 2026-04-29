import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

describe('Invite — /mock/invite controls', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('GET /mock/invite returns config + empty invitations on a fresh server', async function () {
        const res = await fastify.inject({ method: 'GET', url: '/mock/invite' })
        expect(res.statusCode).to.equal(200)
        const data = res.json()
        expect(data.config).to.include({
            error: null,
            error_endpoint: null,
            auto_accept: false,
        })
        expect(data.invitations).to.deep.equal([])
    })

    it('PUT /mock/invite updates fields', async function () {
        const res = await fastify.inject({
            method: 'PUT',
            url: '/mock/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                error: 'invitation_expired',
                error_endpoint: 'invitation',
                auto_accept: true,
                expires_in: 60,
            }),
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().config).to.include({
            error: 'invitation_expired',
            error_endpoint: 'invitation',
            auto_accept: true,
            expires_in: 60,
        })
    })

    it('error scoped to invitation does not affect create', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                error: 'invitation_not_found',
                error_endpoint: 'invitation',
            }),
        })
        const create = await fastify.inject({
            method: 'POST',
            url: '/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                email: 'a@example.com',
                prompt: 'p',
                client_id: 'c1',
            }),
        })
        expect(create.statusCode).to.equal(200)

        const inv = create.json().invite
        const get = await fastify.inject({
            method: 'GET',
            url: `/invitation/${inv.id}`,
        })
        expect(get.json().error).to.equal('invitation_not_found')
    })

    it('DELETE /mock resets config + invitations', async function () {
        await fastify.inject({
            method: 'POST',
            url: '/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                email: 'a@example.com',
                prompt: 'p',
                client_id: 'c1',
            }),
        })
        await fastify.inject({
            method: 'PUT',
            url: '/mock/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_accept: true }),
        })

        await fastify.inject({ method: 'DELETE', url: '/mock' })

        const res = await fastify.inject({ method: 'GET', url: '/mock/invite' })
        const data = res.json()
        expect(data.config.auto_accept).to.equal(false)
        expect(data.invitations).to.deep.equal([])
    })
})
