import { expect } from 'chai'
import pkceChallenge from 'pkce-challenge'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

import { ISSUER } from '../src/config.js'

const { code_challenge, code_verifier } = await pkceChallenge()
const client_id = 'token-test-client'
const nonce = 'token-nonce'
const redirect_uri = 'https://token-redirect'

// Helper to get a valid authorization code with PKCE
async function getAuthCode(usePkce = true) {
    const params = {
        client_id,
        nonce,
        redirect_uri,
        response_type: 'code',
        scope: 'openid',
    }
    if (usePkce) {
        params.code_challenge_method = 'S256'
        params.code_challenge = code_challenge
    }
    const response = await fastify.inject({
        method: 'GET',
        url: '/authorize?' + new URLSearchParams(params),
    })
    const location = response.headers?.location
    return new URL(location).searchParams.get('code')
}

describe('Token Endpoint Error Tests', function() {
    beforeEach(async function() {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('should return invalid_request for missing code', async function() {
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                client_id,
                redirect_uri,
                grant_type: 'authorization_code',
                code_verifier,
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return invalid_grant for unknown code', async function() {
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code: 'non-existent-code',
                client_id,
                redirect_uri,
                grant_type: 'authorization_code',
                code_verifier,
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_grant')
    })

    it('should return invalid_request for missing client_id', async function() {
        const code = await getAuthCode()
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                redirect_uri,
                grant_type: 'authorization_code',
                code_verifier,
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return invalid_request for wrong client_id', async function() {
        const code = await getAuthCode()
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id: 'wrong-client-id',
                redirect_uri,
                grant_type: 'authorization_code',
                code_verifier,
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return invalid_request for missing redirect_uri', async function() {
        const code = await getAuthCode()
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id,
                grant_type: 'authorization_code',
                code_verifier,
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return invalid_request for wrong redirect_uri', async function() {
        const code = await getAuthCode()
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id,
                redirect_uri: 'https://wrong-redirect',
                grant_type: 'authorization_code',
                code_verifier,
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return invalid_request for missing grant_type', async function() {
        const code = await getAuthCode()
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id,
                redirect_uri,
                code_verifier,
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return unsupported_grant_type for wrong grant_type', async function() {
        const code = await getAuthCode()
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id,
                redirect_uri,
                grant_type: 'client_credentials',
                code_verifier,
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('unsupported_grant_type')
    })

    it('should return invalid_grant for wrong code_verifier (PKCE mismatch)', async function() {
        const code = await getAuthCode()
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id,
                redirect_uri,
                grant_type: 'authorization_code',
                code_verifier: 'wrong-verifier-that-does-not-match-challenge-at-all',
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_grant')
    })

    it('should return invalid_request for missing code_verifier when code_challenge exists', async function() {
        const code = await getAuthCode(true)
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id,
                redirect_uri,
                grant_type: 'authorization_code',
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return invalid_request for code_verifier without code_challenge (no PKCE, no client_secret)', async function() {
        const code = await getAuthCode(false)
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id,
                redirect_uri,
                grant_type: 'authorization_code',
                code_verifier: 'some-verifier',
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
    })

    it('should return invalid_request when no PKCE and no client_secret', async function() {
        const code = await getAuthCode(false)
        const response = await fastify.inject({
            url: '/oauth/token',
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            payload: new URLSearchParams({
                code,
                client_id,
                redirect_uri,
                grant_type: 'authorization_code',
            }).toString(),
        })
        expect(response.statusCode).to.equal(400)
        const data = await response.json()
        expect(data.error).to.equal('invalid_request')
        expect(data.error_description).to.include('code_verifier required')
    })
})
