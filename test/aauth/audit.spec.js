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

describe('AAuth /aauth/audit', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('returns 201 for a well-formed audit record', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/audit',
            body: {
                mission: { approver: 'https://ps.example', s256: 'abc' },
                action: 'WebSearch',
                description: 'Searched for flights',
                parameters: { query: 'flights' },
                result: { status: 'completed' },
            },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/audit',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(201)
    })

    it('400 when mission missing', async function () {
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/audit',
            body: { action: 'WebSearch' },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/audit',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(400)
    })
})
