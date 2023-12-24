import { expect } from 'chai'
import pkceChallenge from "pkce-challenge"
import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

import defaultUser from '../src/users.js'
const ISSUER = 'http://mockin'

const { code_challenge, code_verifier } = await pkceChallenge()
const client_id = 'client_id-value'
const nonce = 'nonce-value'
const redirect_uri = 'https://redirect_uri-value'

describe('Mock Error Tests', function() {
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
    describe('GET /authorize', function() {
        it('should return access_denied', async function() {
            // set MOCK.authorize.error
            const putResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/authorize',
                payload: { error: 'access_denied' },
                headers: { 'content-type': 'application/json' }
            })
            expect(putResponse.statusCode).to.equal(200)
            const putData = await putResponse.json()
            expect(putData).to.exist
            expect(putData.MOCK).to.exist
            expect(putData.MOCK).to.deep.equal({
                authorize: { error: 'access_denied' }
            })
            // GET /authorize
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    redirect_uri,
                    response_type: 'id_token',
                    scope: 'openid',
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.not.exist
            const error = responseURL.searchParams.get('error')
            expect(error).to.equal('access_denied')
        })
    })
    describe('POST /oauth/introspect', function() {
        it('should return active:false', async function() {
            // set MOCK.introspect.active
            const putResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/oauth/introspect',
                payload: { active: false },
                headers: { 'content-type': 'application/json' }
            })
            expect(putResponse.statusCode).to.equal(200)
            const putData = await putResponse.json()
            expect(putData).to.exist
            expect(putData.MOCK).to.exist
            expect(putData.MOCK).to.deep.equal({
                introspect: { active: false }
            })
            // id_token
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    redirect_uri,
                    response_type: 'id_token',
                    scope: 'openid',
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            const responseURL = new URL(location)
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.exist
            // POST /oauth/introspect
            const payload = new URLSearchParams({
                token: id_token,
                nonce,
                client_id,
            }).toString()
            const postResponse = await fastify.inject({
                method: 'POST',
                url: '/oauth/introspect',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                payload,
            })
            expect(postResponse.statusCode).to.equal(200)
            const postData = await postResponse.json()
            expect(postData).to.exist
            expect(postData.active).to.exist
            expect(postData.active).to.equal(false)
        })
    })
    describe('POST /oauth/token', function() {
        it('should return invalid_request', async function() {
            // set MOCK.token.error
            const putResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/oauth/token',
                payload: { error: 'invalid_request' },
                headers: { 'content-type': 'application/json' }
            })
            expect(putResponse.statusCode).to.equal(200)
            const putData = await putResponse.json()
            expect(putData).to.exist
            expect(putData.MOCK).to.exist
            expect(putData.MOCK).to.deep.equal({
                token: { error: 'invalid_request' }
            })
            // id_token
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    redirect_uri,
                    response_type: 'code',
                    scope: 'openid',
                    code_challenge
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            const responseURL = new URL(location)
            const code = responseURL.searchParams.get('code')
            expect(code).to.exist
            // POST /oauth/token
            const payload = new URLSearchParams({
                code,
                code_verifier,
                nonce,
                client_id,
                redirect_uri,
                grant_type: 'authorization_code',
            }).toString()
            const postResponse = await fastify.inject({
                method: 'POST',
                url: '/oauth/token',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                payload,
            })
            expect(postResponse.statusCode).to.equal(400)
            const postData = await postResponse.json()
            expect(postData).to.exist
            expect(postData.error).to.exist
            expect(postData.error).to.equal('invalid_request')
        })
    })
})
