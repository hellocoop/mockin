import { expect } from 'chai'
import { decodeProtectedHeader, decodeJwt } from 'jose'
import Fastify from 'fastify'
import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import { signedPost, signedGet, agentPublicJwk } from './helpers.js'

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
            expect(data.auth_token).to.be.a('string')
            expect(data.expires_in).to.equal(3600)
            expect(data).to.not.have.property('refresh_token')

            // Verify token structure
            const header = decodeProtectedHeader(data.auth_token)
            expect(header.alg).to.equal('EdDSA')
            expect(header.typ).to.equal('auth+jwt')
            expect(header.kid).to.be.a('string')

            const claims = decodeJwt(data.auth_token)
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
                payload: JSON.stringify({ error: 'denied' }),
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
            expect(data.error).to.equal('denied')
        })
    })

    describe('Token refresh', function () {
        it('should issue new auth_token for expired auth_token', async function () {
            const { headers, payload } = await signedPost('/aauth/token', {
                auth_token: 'expired-auth-token',
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
            expect(data.auth_token).to.be.a('string')
            expect(data.expires_in).to.be.a('number')
            expect(data).to.not.have.property('refresh_token')
        })
    })

    describe('Interaction required mode', function () {
        it('should return 202 with Location and AAuth headers', async function () {
            await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
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

            expect(response.statusCode).to.equal(202)
            expect(response.headers.location).to.match(/\/aauth\/pending\//)
            expect(response.headers['retry-after']).to.equal('0')
            expect(response.headers['cache-control']).to.equal('no-store')
            expect(response.headers['aauth']).to.match(/^require=interaction; code="/)

            // Verify JSON body
            const data = response.json()
            expect(data.status).to.equal('pending')
            expect(data.location).to.equal(response.headers.location)
            expect(data.require).to.equal('interaction')
            expect(data.code).to.be.a('string')
        })

        it('should issue token after interaction approval + pending poll', async function () {
            await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ auto_grant: false, interaction_required: true }),
            })

            // Step 1: Initial request — get 202 with Location and code
            const init = await signedPost('/aauth/token', { scope: 'openid' })
            const initResponse = await fastify.inject({
                method: 'POST',
                url: '/aauth/token',
                headers: init.headers,
                payload: init.payload,
            })
            expect(initResponse.statusCode).to.equal(202)

            const location = initResponse.headers.location
            const aauth = initResponse.headers['aauth']
            const code = aauth.match(/code="([^"]+)"/)[1]

            // Step 2: User visits interaction endpoint (auto-approves)
            const interactionResponse = await fastify.inject({
                method: 'GET',
                url: `/aauth/interaction?code=${code}`,
            })
            expect(interactionResponse.statusCode).to.equal(200)

            // Step 3: Poll pending endpoint — should get token
            const pendingPath = new URL(location).pathname
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
    })
})
