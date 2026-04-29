import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import { installFetchSink, SINK_URL } from './helpers.js'

const fastify = Fastify()
api(fastify)

async function createInvitation(extra = {}) {
    const res = await fastify.inject({
        method: 'POST',
        url: '/invite',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({
            email: 'invitee@example.com',
            prompt: 'Join us',
            client_id: 'client-abc',
            events_uri: SINK_URL,
            initiate_login_uri: 'https://app.example.com/initiate',
            role: 'subscriber',
            tenant: 'acme',
            state: 'opaque-state',
            ...extra,
        }),
    })
    return res.json().invite
}

describe('Invite — invitation lifecycle', function () {
    let sink
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
        sink = installFetchSink()
    })
    afterEach(function () {
        sink.restore()
    })

    it('GET /invitation/:id returns sanitized', async function () {
        const inv = await createInvitation()
        const res = await fastify.inject({
            method: 'GET',
            url: `/invitation/${inv.id}`,
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json()).to.include({
            id: inv.id,
            invitee: 'invitee@example.com',
            client_id: 'client-abc',
        })
    })

    it('GET /invitation/:id unknown → 200 invitation_not_found', async function () {
        const res = await fastify.inject({
            method: 'GET',
            url: '/invitation/inv_doesnotexist',
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().error).to.equal('invitation_not_found')
    })

    it('GET /invitation/:id expired → 200 invitation_expired', async function () {
        // Create normally, then reach in and backdate expiresAt so we don't
        // pay 2+ seconds of wall time per test run.
        const inv = await createInvitation()
        const { _internal } = await import('../../src/invite.js')
        _internal.invitations.get(inv.id).expiresAt = 1 // long-past epoch
        const res = await fastify.inject({
            method: 'GET',
            url: `/invitation/${inv.id}`,
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().error).to.equal('invitation_expired')
    })

    it('PUT /invitation/:id accepts → returns initiate_login_url + event JWT', async function () {
        const inv = await createInvitation()
        const res = await fastify.inject({
            method: 'PUT',
            url: `/invitation/${inv.id}`,
        })
        expect(res.statusCode).to.equal(200)
        const data = res.json()
        expect(data.initiate_login_url).to.be.a('string')
        const u = new URL(data.initiate_login_url)
        expect(u.searchParams.get('login_hint')).to.equal('invitee@example.com')
        expect(u.searchParams.get('iss')).to.equal(ISSUER)
        expect(data.event).to.be.a('string')
        // SET JWT was POSTed to events_uri
        expect(sink.captured).to.have.lengthOf(1)
        expect(sink.captured[0].headers['Content-Type']).to.equal('application/jwt')
    })

    it('DELETE /invitation/:id declines and removes the invitation', async function () {
        const inv = await createInvitation()
        const res = await fastify.inject({
            method: 'DELETE',
            url: `/invitation/${inv.id}`,
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().success).to.equal(true)

        const after = await fastify.inject({
            method: 'GET',
            url: `/invitation/${inv.id}`,
        })
        expect(after.json().error).to.equal('invitation_not_found')
    })

    it('PUT /invitation/:id without initiate_login_uri returns null url', async function () {
        const inv = await createInvitation({ initiate_login_uri: undefined })
        const res = await fastify.inject({
            method: 'PUT',
            url: `/invitation/${inv.id}`,
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().initiate_login_url).to.be.null
    })
})
