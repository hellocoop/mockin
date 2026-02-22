import { expect } from 'chai'
import { decodeJwt } from 'jose'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

import { ISSUER } from '../src/config.js'

const client_id = 'extended-test-client'
const nonce = 'extended-nonce'
const redirect_uri = 'https://extended-redirect'

const baseParams = {
    client_id,
    nonce,
    redirect_uri,
    response_type: 'id_token',
    scope: 'openid',
}

describe('Authorize Extended Tests', function() {
    beforeEach(async function() {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    describe('code_challenge with id_token response_type', function() {
        it('should return error', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    ...baseParams,
                    response_type: 'id_token',
                    code_challenge: 'some-challenge',
                    code_challenge_method: 'S256',
                }),
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.equal('invalid_request')
            const desc = responseURL.searchParams.get('error_description')
            expect(desc).to.include('code_challenge')
        })
    })

    describe('code_challenge_method not S256', function() {
        it('should return error for plain method', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    ...baseParams,
                    response_type: 'code',
                    code_challenge: 'some-challenge',
                    code_challenge_method: 'plain',
                }),
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.equal('invalid_request')
            const desc = responseURL.searchParams.get('error_description')
            expect(desc).to.include('S256')
        })
    })

    describe('invalid response_type', function() {
        it('should return error for unknown response_type', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    ...baseParams,
                    response_type: 'token',
                }),
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.equal('invalid_request')
            const desc = responseURL.searchParams.get('error_description')
            expect(desc).to.include('response_type')
        })
    })

    describe('duplicate scopes', function() {
        it('should return error', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    ...baseParams,
                    scope: 'openid email email',
                }),
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.equal('invalid_request')
            const desc = responseURL.searchParams.get('error_description')
            expect(desc).to.include('duplicate')
        })
    })

    describe('invalid scopes', function() {
        it('should return error for unrecognized scope', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    ...baseParams,
                    scope: 'openid bogus_scope',
                }),
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.equal('invalid_request')
            const desc = responseURL.searchParams.get('error_description')
            expect(desc).to.include('invalid scopes')
        })
    })

    describe('response_mode=fragment', function() {
        it('should return token in URL hash', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    ...baseParams,
                    response_mode: 'fragment',
                }),
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            const responseURL = new URL(location)
            // Fragment params are in the hash
            const hashParams = new URLSearchParams(responseURL.hash.substring(1))
            const id_token = hashParams.get('id_token')
            expect(id_token).to.exist
            const payload = decodeJwt(id_token)
            expect(payload.iss).to.equal(ISSUER)
            expect(payload.aud).to.equal(client_id)
        })
    })
})
