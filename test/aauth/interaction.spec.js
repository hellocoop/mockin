import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'
import { signedPost } from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('AAuth Interaction Endpoint Tests', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('should return 400 for missing code', async function () {
        const response = await fastify.inject({
            method: 'GET',
            url: '/aauth/interaction',
        })
        expect(response.statusCode).to.equal(400)
        const data = response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return 400 for unknown code', async function () {
        const response = await fastify.inject({
            method: 'GET',
            url: '/aauth/interaction?code=UNKNOWN1',
        })
        expect(response.statusCode).to.equal(400)
        const data = response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should auto-approve and return HTML when no callback', async function () {
        // Configure interaction required
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
        })

        // Get 202 with code
        const init = await signedPost('/aauth/token', { scope: 'openid' })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        const aauth = initResponse.headers['aauth']
        const code = aauth.match(/code="([^"]+)"/)[1]

        // Visit interaction endpoint
        const response = await fastify.inject({
            method: 'GET',
            url: `/aauth/interaction?code=${code}`,
        })
        expect(response.statusCode).to.equal(200)
        expect(response.headers['content-type']).to.include('text/html')
        expect(response.body).to.include('Authorization Approved')
    })

    it('should redirect to callback when provided as query param', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
        })

        const init = await signedPost('/aauth/token', {
            scope: 'openid',
        })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        const aauth = initResponse.headers['aauth']
        const code = aauth.match(/code="([^"]+)"/)[1]

        const response = await fastify.inject({
            method: 'GET',
            url: `/aauth/interaction?code=${code}&callback=${encodeURIComponent('https://agent.example.com/callback')}`,
        })
        expect(response.statusCode).to.equal(302)
        const location = response.headers.location
        expect(location).to.equal('https://agent.example.com/callback')
    })

    it('should deny when mock error is denied', async function () {
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

        const init = await signedPost('/aauth/token', { scope: 'openid' })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        const aauth = initResponse.headers['aauth']
        const code = aauth.match(/code="([^"]+)"/)[1]

        const response = await fastify.inject({
            method: 'GET',
            url: `/aauth/interaction?code=${code}`,
        })
        expect(response.statusCode).to.equal(403)
        const data = response.json()
        expect(data.error).to.equal('denied')
    })
})
