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

describe('AAuth /aauth/interaction', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('completion → 200 acknowledgment', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/interaction',
            body: {
                type: 'completion',
                summary: 'Trip booked',
                mission: { approver: 'https://ps.example', s256: 'abc' },
            },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/interaction',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(200)
        expect(response.json().status).to.equal('received')
    })

    it('question → canned answer', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/interaction',
            body: { type: 'question', question: 'Refundable?' },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/interaction',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(200)
        expect(response.json().answer).to.be.a('string')
    })

    it('interaction → 202 + pending Location', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/interaction',
            body: {
                type: 'interaction',
                description: 'Confirm booking',
                url: 'https://booking.example/confirm',
                code: 'X7K2',
            },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/interaction',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(202)
        expect(response.headers.location).to.match(/\/aauth\/pending\//)
        expect(response.headers['aauth-requirement']).to.equal('requirement=approval')
    })

    it('400 on unknown type', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/interaction',
            body: { type: 'nonsense' },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/interaction',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(400)
    })
})
