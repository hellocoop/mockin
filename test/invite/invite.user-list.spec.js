import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

async function create(body) {
    return fastify.inject({
        method: 'POST',
        url: '/invite',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify(body),
    })
}

describe('Invite — GET /user/invite', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('returns all invitations when no filter is provided', async function () {
        await create({
            email: 'a@example.com', prompt: 'p', client_id: 'c1',
        })
        await create({
            email: 'b@example.com', prompt: 'p', client_id: 'c1',
        })
        const res = await fastify.inject({
            method: 'GET',
            url: '/user/invite',
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().invitations).to.have.lengthOf(2)
    })

    it('filters by inviter_sub when provided', async function () {
        await create({
            email: 'a@example.com', prompt: 'p', client_id: 'c1',
            inviter_sub: 'sub-alice',
        })
        await create({
            email: 'b@example.com', prompt: 'p', client_id: 'c1',
            inviter_sub: 'sub-bob',
        })
        const res = await fastify.inject({
            method: 'GET',
            url: '/user/invite?inviter_sub=sub-alice',
        })
        const list = res.json().invitations
        expect(list).to.have.lengthOf(1)
        expect(list[0].invitee).to.equal('a@example.com')
    })

    it('returns empty list when nothing matches', async function () {
        const res = await fastify.inject({
            method: 'GET',
            url: '/user/invite?inviter_sub=nobody',
        })
        expect(res.json().invitations).to.deep.equal([])
    })
})
