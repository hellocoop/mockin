import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'
import { installFetchSink, SINK_URL } from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('Invite — GET /invite (entry redirect)', function () {
    let sink
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
        sink = installFetchSink()
    })
    afterEach(function () {
        sink.restore()
    })

    it('400 without inviter or client_id', async function () {
        const res = await fastify.inject({
            method: 'GET',
            url: '/invite',
        })
        expect(res.statusCode).to.equal(400)
    })

    it('creates invitation and redirects to return_uri', async function () {
        const params = new URLSearchParams({
            inviter: 'sub-alice',
            client_id: 'c1',
            prompt: 'Join',
            return_uri: 'https://app.example.com/back',
            invitee_email: 'invitee@example.com',
        }).toString()
        const res = await fastify.inject({
            method: 'GET',
            url: `/invite?${params}`,
        })
        expect(res.statusCode).to.equal(302)
        expect(res.headers.location).to.equal('https://app.example.com/back')

        // Invitation is created; fetch via /user/invite
        const list = (await fastify.inject({
            method: 'GET',
            url: '/user/invite',
        })).json().invitations
        expect(list).to.have.lengthOf(1)
        expect(list[0].invitee).to.equal('invitee@example.com')

        // No SET fired without auto_accept
        expect(sink.captured).to.have.lengthOf(0)
    })

    it('returns JSON when no return_uri', async function () {
        const params = new URLSearchParams({
            inviter: 'sub-alice',
            client_id: 'c1',
            invitee_email: 'invitee@example.com',
        }).toString()
        const res = await fastify.inject({
            method: 'GET',
            url: `/invite?${params}`,
        })
        expect(res.statusCode).to.equal(200)
        expect(res.json().invite.invitee).to.equal('invitee@example.com')
    })

    it('auto_accept fires the SET inline', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_accept: true }),
        })
        const params = new URLSearchParams({
            inviter: 'sub-alice',
            client_id: 'c1',
            invitee_email: 'auto@example.com',
            events_uri: SINK_URL,
        }).toString()
        const res = await fastify.inject({
            method: 'GET',
            url: `/invite?${params}`,
        })
        expect(res.statusCode).to.equal(200)
        expect(sink.captured).to.have.lengthOf(1)
        expect(sink.captured[0].body).to.be.a('string').and.match(/^eyJ/)
    })
})
