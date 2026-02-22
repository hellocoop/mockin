import { expect } from 'chai'
import pkceChallenge from "pkce-challenge"
import { decodeJwt, decodeProtectedHeader, jwtVerify, createLocalJWKSet } from 'jose'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

import defaultUser from '../src/users.js'
import { ISSUER } from '../src/config.js'

const { code_challenge, code_verifier } = await pkceChallenge()
const client_id = 'client_id-value'
const nonce = 'nonce-value'
const redirect_uri = 'https://redirect_uri-value'

const injectAuthToken = {
    method: 'GET',
    url: '/authorize?' + new URLSearchParams({
        client_id,
        nonce,
        redirect_uri,
        response_type: 'id_token',
        scope: 'openid',
    })
}

describe('ID Token Error Tests', function() {
    beforeEach(async function() {
        const response = await fastify.inject({
            method: 'DELETE',
            url: '/mock',
        })
        expect(response.statusCode).to.equal(200)
    })
    afterEach(async function() {
        const response = await fastify.inject({
            method: 'DELETE',
            url: '/mock',
        })
        expect(response.statusCode).to.equal(200)
    })

    describe('ID Token "iss"', function() {
        it(`should not be ${ISSUER}`, async function() {
            const mockResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/token?iss=http://not-issuer',
            })
            expect(mockResponse.statusCode).to.equal(200)

            const response = await fastify.inject(injectAuthToken)
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.exist
            const { iss } = decodeJwt(id_token)
            expect(iss).to.exist
            expect(iss).to.not.equal(ISSUER)
        })
    })
    describe('ID Token "aud"', function() {
        it(`should not be ${client_id}`, async function() {
            const mockResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/token?aud=not-client_id',
            })
            expect(mockResponse.statusCode).to.equal(200)

            const response = await fastify.inject(injectAuthToken)
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.exist
            const { aud } = decodeJwt(id_token)
            expect(aud).to.exist
            expect(aud).to.not.equal(client_id)
        })
    })
    describe('ID Token', function() {
        it('should be expired', async function() {
            const mockResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/token?expired=true',
            })
            expect(mockResponse.statusCode).to.equal(200)

            const response = await fastify.inject(injectAuthToken)
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.exist
            const { iat, exp } = decodeJwt(id_token)
            expect(iat).to.exist
            expect(exp).to.exist
            expect(exp - iat).to.equal(5*60) // 5 minutes
            const now = Math.floor(Date.now()/1000)
            expect(now).to.be.greaterThan(exp)
        })
    })
    describe('ID Token', function() {
        it('should be signed with wrong key', async function() {
            const mockResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/token?wrongKey=true',
            })
            expect(mockResponse.statusCode).to.equal(200)

            const response = await fastify.inject(injectAuthToken)
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.exist
            const header = decodeProtectedHeader(id_token)
            expect(header).to.exist
            const { kid } = header
            expect(kid).to.exist
            const jwksResponse = await fastify.inject({
                url: '/jwks',
                method: 'GET',
            })
            expect(jwksResponse.statusCode).to.equal(200)
            const jwks = await jwksResponse.json()
            expect(jwks).to.exist
            const JWKS = createLocalJWKSet(jwks)
            try {
                const result = await jwtVerify(id_token, JWKS)
                expect(result).to.not.exist // should not get here
            } catch (err) { // we expect to get an error
                expect(err).to.exist
                expect(err.message).to.include('signature verification failed')
            }
        })
    })
})
