import { expect } from 'chai'
import pkceChallenge from 'pkce-challenge'
import { decodeJwt } from 'jose'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

import defaultUser from '../src/users.js'
import { ISSUER } from '../src/config.js'

const { code_challenge, code_verifier } = await pkceChallenge()
const client_id = 'userinfo-test-client'
const nonce = 'userinfo-nonce'
const redirect_uri = 'https://userinfo-redirect'

// Helper to get a valid access_token via code flow
async function getAccessToken() {
    const authResponse = await fastify.inject({
        method: 'GET',
        url: '/authorize?' + new URLSearchParams({
            client_id,
            nonce,
            redirect_uri,
            response_type: 'code',
            scope: 'openid name email',
            code_challenge_method: 'S256',
            code_challenge,
        }),
    })
    const location = authResponse.headers?.location
    const code = new URL(location).searchParams.get('code')
    const tokenResponse = await fastify.inject({
        url: '/oauth/token',
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({
            code,
            client_id,
            redirect_uri,
            grant_type: 'authorization_code',
            code_verifier,
        }).toString(),
    })
    const data = await tokenResponse.json()
    return data.access_token
}

describe('UserInfo Endpoint Tests', function() {
    beforeEach(async function() {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    describe('GET /oauth/userinfo', function() {
        it('should return user info with valid token', async function() {
            const access_token = await getAccessToken()
            const response = await fastify.inject({
                url: '/oauth/userinfo',
                method: 'GET',
                headers: { authorization: `Bearer ${access_token}` },
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data.sub).to.equal(defaultUser.sub)
            expect(data.iss).to.equal(ISSUER)
            expect(data.name).to.equal(defaultUser.name)
            expect(data.email).to.equal(defaultUser.email)
        })
    })

    describe('POST /oauth/userinfo', function() {
        it('should return same data as GET', async function() {
            const access_token = await getAccessToken()
            const getResponse = await fastify.inject({
                url: '/oauth/userinfo',
                method: 'GET',
                headers: { authorization: `Bearer ${access_token}` },
            })
            // Need a fresh token since code is one-time use
            // Instead, use the same token for POST
            const postResponse = await fastify.inject({
                url: '/oauth/userinfo',
                method: 'POST',
                headers: { authorization: `Bearer ${access_token}` },
            })
            expect(postResponse.statusCode).to.equal(200)
            const getData = await getResponse.json()
            const postData = await postResponse.json()
            expect(postData.sub).to.equal(getData.sub)
            expect(postData.iss).to.equal(getData.iss)
            expect(postData.name).to.equal(getData.name)
            expect(postData.email).to.equal(getData.email)
        })
    })

    describe('Error handling', function() {
        it('should return 400 for missing Authorization header', async function() {
            const response = await fastify.inject({
                url: '/oauth/userinfo',
                method: 'GET',
            })
            expect(response.statusCode).to.equal(400)
            const data = await response.json()
            expect(data.error).to.equal('invalid_request')
        })

        it('should return 400 for Authorization without Bearer prefix', async function() {
            const response = await fastify.inject({
                url: '/oauth/userinfo',
                method: 'GET',
                headers: { authorization: 'Basic abc123' },
            })
            expect(response.statusCode).to.equal(400)
            const data = await response.json()
            expect(data.error).to.equal('invalid_request')
        })

        it('should return 400 for Bearer with empty value', async function() {
            const response = await fastify.inject({
                url: '/oauth/userinfo',
                method: 'GET',
                headers: { authorization: 'Bearer ' },
            })
            expect(response.statusCode).to.equal(400)
            const data = await response.json()
            expect(data.error).to.equal('invalid_request')
        })

        it('should return 401 for invalid token', async function() {
            const response = await fastify.inject({
                url: '/oauth/userinfo',
                method: 'GET',
                headers: { authorization: 'Bearer invalid.jwt.token' },
            })
            expect(response.statusCode).to.equal(401)
            const data = await response.json()
            expect(data.error).to.equal('invalid_token')
        })
    })
})
