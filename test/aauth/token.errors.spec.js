// /aauth/token error paths — bad signatures, mismatched claims, mock errors.

import { expect } from 'chai'
import Fastify from 'fastify'

import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import {
    installMocks,
    mintAgentToken,
    mintResourceToken,
    signedRequest,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('AAuth /aauth/token — errors', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('401 + Accept-Signature when no signature is present', async function () {
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ resource_token: 'x' }),
        })
        expect(response.statusCode).to.equal(401)
        expect(response.headers['accept-signature']).to.be.a('string')
        expect(response.json().error).to.equal('signature_required')
    })

    it('401 invalid_jwt when agent_token signature is bad', async function () {
        // Mint a token then corrupt its signature (last segment).
        const real = await mintAgentToken()
        const segs = real.split('.')
        segs[2] = 'AAAAAAAAAAAAAAAAAAAAAA'
        const tampered = segs.join('.')

        const resourceToken = await mintResourceToken({ scope: 'openid' })
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/token',
            body: { resource_token: resourceToken },
            agentToken: tampered,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers,
            payload,
        })
        // The HTTPSig step verifies the HTTP signature using cnf.jwk from
        // the JWT — that still passes because we used the real ephemeral
        // key — and then mockin rejects because the JWT signature itself
        // is invalid.
        expect(response.statusCode).to.equal(401)
        expect(response.json().error).to.equal('invalid_jwt')
    })

    it('400 invalid_request when resource_token missing', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/token',
            body: {},
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_request')
    })

    it('400 invalid_resource_token when aud != PS', async function () {
        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({
            scope: 'openid',
            aud: 'https://wrong-ps.example',
        })
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/token',
            body: { resource_token: resourceToken },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_resource_token')
        expect(response.json().error_description).to.match(/aud/)
    })

    it('400 invalid_resource_token when agent_jkt mismatches HTTPSig key', async function () {
        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({
            scope: 'openid',
            agent_jkt: 'wrongthumbprint',
        })
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/token',
            body: { resource_token: resourceToken },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error_description).to.match(/agent_jkt/)
    })

    it('400 invalid_resource_token when agent claim mismatches agent_token sub', async function () {
        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({
            scope: 'openid',
            agent: 'aauth:other@somewhere.example',
        })
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/token',
            body: { resource_token: resourceToken },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error_description).to.match(/agent/)
    })

    it('returns mock-injected error code', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ error: 'denied' }),
        })

        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({ scope: 'openid' })
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/token',
            body: { resource_token: resourceToken },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(403)
        expect(response.json().error).to.equal('denied')
    })

    it('scopes mock error to a specific endpoint', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                error: 'denied',
                error_endpoint: 'permission',
            }),
        })

        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({ scope: 'openid' })
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/token',
            body: { resource_token: resourceToken },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers,
            payload,
        })
        // Token endpoint not impacted; permission endpoint would be.
        expect(response.statusCode).to.equal(200)
    })
})
