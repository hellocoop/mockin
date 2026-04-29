import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

const minimal = {
    email: 'invitee@example.com',
    prompt: 'Subscriber to example.com',
    client_id: 'client-abc',
}

async function post(body) {
    return fastify.inject({
        method: 'POST',
        url: '/invite',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify(body),
    })
}

describe('Invite — POST /invite', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('creates an invitation with the canonical sanitized response', async function () {
        const res = await post(minimal)
        expect(res.statusCode).to.equal(200)
        const data = res.json()
        expect(data.invite).to.include({
            invitee: 'invitee@example.com',
            prompt: 'Subscriber to example.com',
            client_id: 'client-abc',
        })
        expect(data.invite.id).to.match(/^inv_/)
        expect(data.invite.expiresAt).to.be.a('number')
        expect(data.invite.createdAt).to.be.a('number')
        expect(data.invite.lastEmailedAt).to.equal(data.invite.createdAt)
    })

    it('400 when email missing', async function () {
        const res = await post({ ...minimal, email: undefined })
        expect(res.statusCode).to.equal(400)
        expect(res.json().error).to.equal('invalid_request')
    })

    it('400 when prompt missing', async function () {
        const res = await post({ ...minimal, prompt: undefined })
        expect(res.statusCode).to.equal(400)
    })

    it('400 when client_id missing', async function () {
        const res = await post({ ...minimal, client_id: undefined })
        expect(res.statusCode).to.equal(400)
    })

    it('400 invalid_email on garbage email', async function () {
        const res = await post({ ...minimal, email: 'not-an-email' })
        expect(res.statusCode).to.equal(400)
        expect(res.json().error).to.equal('invalid_email')
    })

    it('400 email_too_long when > 320 chars', async function () {
        const long = 'a'.repeat(310) + '@example.com'
        const res = await post({ ...minimal, email: long })
        expect(res.statusCode).to.equal(400)
        expect(res.json().error).to.equal('email_too_long')
    })

    it('honours mock-injected error', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ error: 'invalid_request' }),
        })
        const res = await post(minimal)
        expect(res.statusCode).to.equal(400)
        expect(res.json().error).to.equal('invalid_request')
    })

    it('disposable_email returns 200 (warning), not 400', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ error: 'disposable_email' }),
        })
        const res = await post(minimal)
        expect(res.statusCode).to.equal(200)
        expect(res.json().error).to.equal('disposable_email')
    })
})
