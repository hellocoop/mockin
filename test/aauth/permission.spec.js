import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'
import {
    installMocks,
    mintAgentToken,
    signedRequest,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('AAuth /aauth/permission', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('grants by default', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/permission',
            body: {
                action: 'SendEmail',
                description: 'Send the itinerary',
                parameters: { to: 'user@example.com' },
            },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/permission',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(200)
        expect(response.json()).to.deep.equal({ permission: 'granted' })
    })

    it('denies when mock.permission=denied', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                permission: 'denied',
                permission_reason: 'tool not on allowlist',
            }),
        })
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/permission',
            body: { action: 'DeleteEverything' },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/permission',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(200)
        expect(response.json().permission).to.equal('denied')
        expect(response.json().reason).to.equal('tool not on allowlist')
    })

    it('400 when action missing', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/permission',
            body: {},
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/permission',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_request')
    })
})
