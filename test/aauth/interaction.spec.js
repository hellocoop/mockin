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

    it('should return 400 for missing interaction_ticket', async function () {
        const response = await fastify.inject({
            method: 'GET',
            url: '/aauth/interaction',
        })
        expect(response.statusCode).to.equal(400)
        const data = response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return 400 for unknown interaction_ticket', async function () {
        const response = await fastify.inject({
            method: 'GET',
            url: '/aauth/interaction?interaction_ticket=unknown-ticket',
        })
        expect(response.statusCode).to.equal(400)
        const data = response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should auto-approve and return HTML when no callback_url', async function () {
        // Configure interaction required
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
        })

        // Get tickets
        const init = await signedPost('/aauth/token', { scope: 'openid' })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        const { interaction_ticket } = initResponse.json()

        // Visit interaction endpoint
        const response = await fastify.inject({
            method: 'GET',
            url: `/aauth/interaction?interaction_ticket=${interaction_ticket}`,
        })
        expect(response.statusCode).to.equal(200)
        expect(response.headers['content-type']).to.include('text/html')
        expect(response.body).to.include('Authorization Approved')
    })

    it('should redirect to callback_url when provided', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
        })

        const init = await signedPost('/aauth/token', {
            scope: 'openid',
            callback_url: 'https://agent.example.com/callback',
            callback_ticket: 'my-callback-ticket',
        })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        const { interaction_ticket } = initResponse.json()

        const response = await fastify.inject({
            method: 'GET',
            url: `/aauth/interaction?interaction_ticket=${interaction_ticket}`,
        })
        expect(response.statusCode).to.equal(302)
        const location = response.headers.location
        expect(location).to.include('https://agent.example.com/callback')
        expect(location).to.include('callback_ticket=my-callback-ticket')
    })

    it('should deny when mock error is access_denied', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                auto_grant: false,
                interaction_required: true,
                error: 'access_denied',
            }),
        })

        const init = await signedPost('/aauth/token', { scope: 'openid' })
        const initResponse = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: init.headers,
            payload: init.payload,
        })
        const { interaction_ticket } = initResponse.json()

        const response = await fastify.inject({
            method: 'GET',
            url: `/aauth/interaction?interaction_ticket=${interaction_ticket}`,
        })
        expect(response.statusCode).to.equal(403)
        const data = response.json()
        expect(data.error).to.equal('access_denied')
    })
})
