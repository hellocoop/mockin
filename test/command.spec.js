import { expect } from 'chai'
import { decodeJwt, decodeProtectedHeader, jwtVerify, createLocalJWKSet } from 'jose'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

import { ISSUER } from '../src/config.js'
import jwks from '../src/mock.jwks.js'
const JWKS = createLocalJWKSet(jwks)

describe('Command Token Tests', function() {
    beforeEach(async function() {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    describe('GET /command/mock', function() {
        it('should return a command token', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/command/mock',
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data).to.exist
            expect(data.command_token).to.be.a('string')
        })

        it('should have typ command+jwt and alg RS256 in header', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/command/mock',
            })
            const { command_token } = await response.json()
            const header = decodeProtectedHeader(command_token)
            expect(header.typ).to.equal('command+jwt')
            expect(header.alg).to.equal('RS256')
            expect(header.kid).to.exist
        })

        it('should have correct payload fields', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/command/mock',
            })
            const { command_token } = await response.json()
            const payload = decodeJwt(command_token)
            expect(payload.iss).to.equal(ISSUER)
            expect(payload.aud).to.equal('test-app')
            expect(payload.command).to.equal('metadata')
            expect(payload.tenant).to.equal('personal')
            expect(payload.jti).to.be.a('string')
            expect(payload.iat).to.be.a('number')
            expect(payload.exp).to.be.a('number')
        })

        it('should default aud to test-app when no client_id', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/command/mock',
            })
            const { command_token } = await response.json()
            const payload = decodeJwt(command_token)
            expect(payload.aud).to.equal('test-app')
        })

        it('should use custom client_id as aud', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/command/mock?client_id=my-custom-app',
            })
            const { command_token } = await response.json()
            const payload = decodeJwt(command_token)
            expect(payload.aud).to.equal('my-custom-app')
        })

        it('should verify against JWKS', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/command/mock',
            })
            const { command_token } = await response.json()
            const { payload } = await jwtVerify(command_token, JWKS, {
                algorithms: ['RS256'],
                issuer: ISSUER,
                audience: 'test-app',
            })
            expect(payload).to.exist
            expect(payload.command).to.equal('metadata')
        })
    })
})
