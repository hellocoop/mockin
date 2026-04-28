// R3 PS token flow — resource_token carries r3_uri + r3_s256. The PS
// fetches the document, hash-verifies it, and embeds r3_granted /
// r3_conditional / r3_uri / r3_s256 on the issued auth_token.

import { expect } from 'chai'
import { decodeJwt } from 'jose'
import Fastify from 'fastify'

import api from '../../src/api.js'
import {
    installMocks,
    mintAgentToken,
    mintResourceToken,
    registerR3Document,
    signedRequest,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

const sampleR3 = {
    vocabulary: 'urn:aauth:vocabulary:openapi',
    operations: [
        { operationId: 'listNotes', method: 'GET', path: '/notes' },
        { operationId: 'createNote', method: 'POST', path: '/notes' },
    ],
}

describe('AAuth /aauth/token — R3 flow', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('grants every operation in the R3 document by default', async function () {
        const r3_uri = 'https://rs.example/r3/abc'
        const { r3_s256 } = await registerR3Document(fastify, r3_uri, sampleR3)

        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({
            scope: 'whoami',
            r3_uri,
            r3_s256,
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
        expect(response.statusCode).to.equal(200)

        const claims = decodeJwt(response.json().auth_token)
        expect(claims.r3_uri).to.equal(r3_uri)
        expect(claims.r3_s256).to.equal(r3_s256)
        expect(claims.r3_granted).to.deep.equal({
            vocabulary: sampleR3.vocabulary,
            operations: sampleR3.operations,
        })
        expect(claims.r3_conditional).to.be.undefined
    })

    it('rejects when r3_s256 does not match the served document', async function () {
        const r3_uri = 'https://rs.example/r3/mismatch'
        await registerR3Document(fastify, r3_uri, sampleR3)

        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({
            scope: 'whoami',
            r3_uri,
            r3_s256: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
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
        expect(response.json().error_description).to.match(/r3_s256/i)
    })

    it('honours r3_grants override (mock)', async function () {
        const r3_uri = 'https://rs.example/r3/override'
        const { r3_s256 } = await registerR3Document(fastify, r3_uri, sampleR3)

        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                r3_grants: {
                    granted: {
                        vocabulary: sampleR3.vocabulary,
                        operations: [sampleR3.operations[0]],
                    },
                    conditional: {
                        vocabulary: sampleR3.vocabulary,
                        operations: [sampleR3.operations[1]],
                    },
                },
            }),
        })

        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({
            scope: 'whoami', r3_uri, r3_s256,
        })
        const { headers, payload } = await signedRequest({
            method: 'POST', path: '/aauth/token',
            body: { resource_token: resourceToken },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST', url: '/aauth/token', headers, payload,
        })
        expect(response.statusCode).to.equal(200)
        const claims = decodeJwt(response.json().auth_token)
        expect(claims.r3_granted.operations).to.have.lengthOf(1)
        expect(claims.r3_conditional.operations).to.have.lengthOf(1)
    })

    it('rejects when only one of r3_uri/r3_s256 is set', async function () {
        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({
            scope: 'whoami',
            r3_uri: 'https://rs.example/r3/x',
            // r3_s256 missing
        })
        const { headers, payload } = await signedRequest({
            method: 'POST', path: '/aauth/token',
            body: { resource_token: resourceToken },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST', url: '/aauth/token', headers, payload,
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_resource_token')
    })
})
