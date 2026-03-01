import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import { signedPost, signedGet } from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('AAuth Pending Endpoint Tests', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('should return 404 for unknown pending id', async function () {
        const { headers } = await signedGet('/aauth/pending/unknown-id')
        const response = await fastify.inject({
            method: 'GET',
            url: '/aauth/pending/unknown-id',
            headers,
        })
        expect(response.statusCode).to.equal(404)
        const data = response.json()
        expect(data.error).to.equal('not_found')
    })

    it('should return 202 while pending', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
        })

        // Create a pending request
        const init = await signedPost('/aauth/token', { scope: 'openid' })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        expect(initResponse.statusCode).to.equal(202)

        const location = initResponse.headers.location
        const pendingPath = new URL(location).pathname

        // Poll before interaction
        const poll = await signedGet(pendingPath)
        const pollResponse = await fastify.inject({
            method: 'GET',
            url: pendingPath,
            headers: poll.headers,
        })

        expect(pollResponse.statusCode).to.equal(202)
        expect(pollResponse.headers.location).to.include('/aauth/pending/')
        expect(pollResponse.headers['retry-after']).to.equal('5')
        expect(pollResponse.headers['cache-control']).to.equal('no-store')

        // Verify JSON body
        const data = pollResponse.json()
        expect(data.status).to.equal('pending')
        expect(data.location).to.equal(pollResponse.headers.location)
    })

    it('should return 200 with auth_token after approval', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
        })

        // Create pending request
        const init = await signedPost('/aauth/token', { scope: 'openid' })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        const location = initResponse.headers.location
        const pendingPath = new URL(location).pathname
        const aauth = initResponse.headers['aauth']
        const code = aauth.match(/code="([^"]+)"/)[1]

        // Approve via interaction
        await fastify.inject({
            method: 'GET',
            url: `/aauth/interaction?code=${code}`,
        })

        // Poll — should get token
        const poll = await signedGet(pendingPath)
        const pollResponse = await fastify.inject({
            method: 'GET',
            url: pendingPath,
            headers: poll.headers,
        })

        expect(pollResponse.statusCode).to.equal(200)
        const data = pollResponse.json()
        expect(data.auth_token).to.be.a('string')
        expect(data.expires_in).to.be.a('number')
        expect(data).to.not.have.property('refresh_token')
    })

    it('should return 403 with error denied after denial', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                auto_grant: false,
                interaction_required: true,
                error: 'denied',
            }),
        })

        // Create pending request
        const init = await signedPost('/aauth/token', { scope: 'openid' })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        const location = initResponse.headers.location
        const pendingPath = new URL(location).pathname
        const aauth = initResponse.headers['aauth']
        const code = aauth.match(/code="([^"]+)"/)[1]

        // Visit interaction — triggers denial
        await fastify.inject({
            method: 'GET',
            url: `/aauth/interaction?code=${code}`,
        })

        // Poll — should get denied
        const poll = await signedGet(pendingPath)
        const pollResponse = await fastify.inject({
            method: 'GET',
            url: pendingPath,
            headers: poll.headers,
        })

        expect(pollResponse.statusCode).to.equal(403)
        const data = pollResponse.json()
        expect(data.error).to.equal('denied')
    })
})
