// Deferred-mode polling — when mock.requirement is set, /aauth/token
// returns 202 with a pending Location. The first poll auto-resolves and
// returns the auth_token (mockin auto-approves on the agent's behalf).

import { expect } from 'chai'
import { decodeJwt } from 'jose'
import Fastify from 'fastify'

import api from '../../src/api.js'
import {
    installMocks,
    mintAgentToken,
    mintResourceToken,
    signedRequest,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

async function setRequirement(req) {
    await fastify.inject({
        method: 'PUT',
        url: '/mock/aauth',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ requirement: req }),
    })
}

async function startTokenRequest() {
    const agentToken = await mintAgentToken()
    const resourceToken = await mintResourceToken({ scope: 'openid email' })
    const { headers, payload } = await signedRequest({
        method: 'POST',
        path: '/aauth/token',
        body: { resource_token: resourceToken },
        agentToken,
    })
    return { agentToken, response: await fastify.inject({
        method: 'POST',
        url: '/aauth/token',
        headers,
        payload,
    }) }
}

describe('AAuth /aauth/pending — deferred mode', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('interaction requirement: 202 → poll → auth_token', async function () {
        await setRequirement('interaction')

        const { agentToken, response: init } = await startTokenRequest()
        expect(init.statusCode).to.equal(202)
        expect(init.headers.location).to.match(/\/aauth\/pending\//)
        expect(init.headers['aauth-requirement']).to.match(/requirement=interaction/)
        expect(init.headers['aauth-requirement']).to.match(/code="/)

        const path = new URL(init.headers.location).pathname
        const { headers: pollHeaders } = await signedRequest({
            method: 'GET',
            path,
            agentToken,
        })
        const poll = await fastify.inject({
            method: 'GET',
            url: path,
            headers: pollHeaders,
        })
        expect(poll.statusCode).to.equal(200)
        const data = poll.json()
        expect(data.auth_token).to.be.a('string')
        const claims = decodeJwt(data.auth_token)
        expect(claims.email).to.exist
    })

    it('approval requirement: 202 → poll → auth_token', async function () {
        await setRequirement('approval')

        const { agentToken, response: init } = await startTokenRequest()
        expect(init.statusCode).to.equal(202)
        expect(init.headers['aauth-requirement']).to.equal('requirement=approval')

        const path = new URL(init.headers.location).pathname
        const { headers: pollHeaders } = await signedRequest({
            method: 'GET',
            path,
            agentToken,
        })
        const poll = await fastify.inject({
            method: 'GET',
            url: path,
            headers: pollHeaders,
        })
        expect(poll.statusCode).to.equal(200)
        expect(poll.json().auth_token).to.be.a('string')
    })

    it('clarification requirement: 202 → poll waits → POST clarification → token', async function () {
        await setRequirement('clarification')

        const { agentToken, response: init } = await startTokenRequest()
        expect(init.statusCode).to.equal(202)
        expect(init.headers['aauth-requirement']).to.equal('requirement=clarification')
        expect(init.json().clarification).to.be.a('string')

        const path = new URL(init.headers.location).pathname

        // First poll still pending — clarification not answered yet.
        const { headers: pollHeaders } = await signedRequest({
            method: 'GET',
            path,
            agentToken,
        })
        const stillPending = await fastify.inject({
            method: 'GET',
            url: path,
            headers: pollHeaders,
        })
        expect(stillPending.statusCode).to.equal(202)
        expect(stillPending.json().status).to.equal('pending')

        // Agent answers the clarification.
        const { headers: postHeaders, payload } = await signedRequest({
            method: 'POST',
            path,
            body: { clarification_response: 'because the user asked.' },
            agentToken,
        })
        const ack = await fastify.inject({
            method: 'POST',
            url: path,
            headers: postHeaders,
            payload,
        })
        expect(ack.statusCode).to.equal(202)

        // Subsequent poll returns the token.
        const { headers: pollHeaders2 } = await signedRequest({
            method: 'GET',
            path,
            agentToken,
        })
        const final = await fastify.inject({
            method: 'GET',
            url: path,
            headers: pollHeaders2,
        })
        expect(final.statusCode).to.equal(200)
        expect(final.json().auth_token).to.be.a('string')
    })

    it('DELETE cancels the pending request', async function () {
        await setRequirement('approval')
        const { agentToken, response: init } = await startTokenRequest()
        const path = new URL(init.headers.location).pathname

        const { headers: delHeaders } = await signedRequest({
            method: 'DELETE',
            path,
            agentToken,
        })
        const del = await fastify.inject({
            method: 'DELETE',
            url: path,
            headers: delHeaders,
        })
        expect(del.statusCode).to.equal(204)

        const { headers: pollHeaders } = await signedRequest({
            method: 'GET',
            path,
            agentToken,
        })
        const poll = await fastify.inject({
            method: 'GET',
            url: path,
            headers: pollHeaders,
        })
        expect(poll.statusCode).to.equal(410)
    })

    it('GET on unknown id returns 404', async function () {
        const agentToken = await mintAgentToken()
        const { headers } = await signedRequest({
            method: 'GET',
            path: '/aauth/pending/does-not-exist',
            agentToken,
        })
        const response = await fastify.inject({
            method: 'GET',
            url: '/aauth/pending/does-not-exist',
            headers,
        })
        expect(response.statusCode).to.equal(404)
    })
})
