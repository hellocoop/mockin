import { expect } from 'chai'
import { decodeProtectedHeader, decodeJwt } from 'jose'
import Fastify from 'fastify'
import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import { signedPost, agentPublicJwk } from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('AAuth Token Endpoint Tests', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    describe('Auto-grant mode (default)', function () {
        it('should issue auth+jwt token for signed request', async function () {
            const { headers, payload } = await signedPost('/aauth/token', {
                scope: 'openid email',
                resource: 'https://api.example.com',
            })

            const response = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers,
                payload,
            })

            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.access_token).to.be.a('string')
            expect(data.token_type).to.equal('auth+jwt')
            expect(data.expires_in).to.equal(3600)
            expect(data.refresh_token).to.be.a('string')
            expect(data.scope).to.equal('openid email')

            // Verify token structure
            const header = decodeProtectedHeader(data.access_token)
            expect(header.alg).to.equal('EdDSA')
            expect(header.typ).to.equal('auth+jwt')
            expect(header.kid).to.be.a('string')

            const claims = decodeJwt(data.access_token)
            expect(claims.iss).to.equal(ISSUER)
            expect(claims.aud).to.equal('https://api.example.com')
            expect(claims.sub).to.be.a('string')
            expect(claims.agent).to.be.a('string')
            expect(claims.cnf).to.be.an('object')
            expect(claims.cnf.jwk).to.be.an('object')
            expect(claims.scope).to.equal('openid email')
            expect(claims.jti).to.be.a('string')
            expect(claims.iat).to.be.a('number')
            expect(claims.exp).to.be.a('number')
        })
    })

    describe('Mock error mode', function () {
        it('should return error when mock error is set', async function () {
            await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ error: 'access_denied' }),
            })

            const { headers, payload } = await signedPost('/aauth/token', {
                scope: 'openid',
            })

            const response = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers,
                payload,
            })

            expect(response.statusCode).to.equal(400)
            const data = response.json()
            expect(data.error).to.equal('access_denied')
        })
    })

    describe('Refresh token', function () {
        it('should issue new token for refresh_token request', async function () {
            const { headers, payload } = await signedPost('/aauth/token', {
                refresh_token: 'some-refresh-token',
                scope: 'openid',
            })

            const response = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers,
                payload,
            })

            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.access_token).to.be.a('string')
            expect(data.token_type).to.equal('auth+jwt')
        })
    })

    describe('Interaction required mode', function () {
        it('should return tickets when interaction is required', async function () {
            await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
            })

            const { headers, payload } = await signedPost('/aauth/token', {
                scope: 'openid',
                callback_url: 'https://agent.example.com/callback',
            })

            const response = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers,
                payload,
            })

            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.request_ticket).to.be.a('string')
            expect(data.interaction_ticket).to.be.a('string')
            expect(data.interaction_endpoint).to.equal(`${ISSUER}/aauth/interaction`)
        })

        it('should return pending on poll before interaction', async function () {
            await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
            })

            // Initial request
            const init = await signedPost('/aauth/token', { scope: 'openid' })
            const initResponse = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers: init.headers,
                payload: init.payload,
            })
            const { request_ticket } = initResponse.json()

            // Poll before interaction
            const poll = await signedPost('/aauth/token', { request_ticket })
            const pollResponse = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers: poll.headers,
                payload: poll.payload,
            })

            expect(pollResponse.statusCode).to.equal(200)
            const data = pollResponse.json()
            expect(data.status).to.equal('pending')
        })

        it('should issue token after interaction approval + poll', async function () {
            await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
            })

            // Step 1: Initial request to get tickets
            const init = await signedPost('/aauth/token', { scope: 'openid' })
            const initResponse = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers: init.headers,
                payload: init.payload,
            })
            const { request_ticket, interaction_ticket } = initResponse.json()

            // Step 2: User visits interaction endpoint (auto-approves)
            const interactionResponse = await fastify.inject({
                method: 'GET',
                url: `/aauth/interaction?interaction_ticket=${interaction_ticket}`,
            })
            expect(interactionResponse.statusCode).to.equal(200)

            // Step 3: Poll — should get token
            const poll = await signedPost('/aauth/token', { request_ticket })
            const pollResponse = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers: poll.headers,
                payload: poll.payload,
            })

            expect(pollResponse.statusCode).to.equal(200)
            const data = pollResponse.json()
            expect(data.access_token).to.be.a('string')
            expect(data.token_type).to.equal('auth+jwt')
        })
    })
})
