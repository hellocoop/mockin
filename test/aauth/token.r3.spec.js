// R3 PS token flow — resource_token carries r3_uri + r3_s256. The PS
// fetches the document, hash-verifies it, and embeds r3_granted /
// r3_per_call / r3_uri / r3_s256 on the issued auth_token.
//
// R3 -02: the claim is `r3_per_call` (was `r3_conditional`), the document
// has no `version` field, and a per-call proposal is a full R3 document
// carrying a REQUIRED `parameters` object.

import { expect } from 'chai'
import { decodeJwt } from 'jose'
import Fastify from 'fastify'

import api from '../../src/api.js'
import {
    installMocks,
    registerR3Document,
    signedRequest,
    personAndResourceToken,
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

// Every request needs a person token first — the resource token has to
// name one this PS issued.
async function postToken(resource) {
    const { agentToken, resourceToken } =
        await personAndResourceToken(fastify, { resource })
    const { headers, payload } = await signedRequest({
        method: 'POST',
        path: '/aauth/token',
        body: { resource_token: resourceToken },
        agentToken,
    })
    return fastify.inject({
        method: 'POST', url: '/aauth/token', headers, payload,
    })
}

describe('AAuth /aauth/token — R3 flow', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('grants every operation in the R3 document by default', async function () {
        const r3_uri = 'https://rs.example/r3/abc'
        const { r3_s256 } = await registerR3Document(fastify, r3_uri, sampleR3)

        const response = await postToken({ scope: 'whoami', r3_uri, r3_s256 })
        expect(response.statusCode).to.equal(200)

        const claims = decodeJwt(response.json().auth_token)
        expect(claims.r3_uri).to.equal(r3_uri)
        expect(claims.r3_s256).to.equal(r3_s256)
        expect(claims.r3_granted).to.deep.equal({
            vocabulary: sampleR3.vocabulary,
            operations: sampleR3.operations,
        })
        expect(claims.r3_per_call).to.be.undefined
    })

    it('rejects when r3_s256 does not match the served document', async function () {
        const r3_uri = 'https://rs.example/r3/mismatch'
        await registerR3Document(fastify, r3_uri, sampleR3)

        const response = await postToken({
            scope: 'whoami',
            r3_uri,
            r3_s256: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_resource_token')
        expect(response.json().detail).to.match(/r3_s256/i)
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
                    per_call: {
                        vocabulary: sampleR3.vocabulary,
                        operations: [sampleR3.operations[1]],
                    },
                },
            }),
        })

        const response = await postToken({ scope: 'whoami', r3_uri, r3_s256 })
        expect(response.statusCode).to.equal(200)
        const claims = decodeJwt(response.json().auth_token)
        expect(claims.r3_granted.operations).to.have.lengthOf(1)
        expect(claims.r3_per_call.operations).to.have.lengthOf(1)
    })

    it('rejects when only one of r3_uri/r3_s256 is set', async function () {
        const response = await postToken({
            scope: 'whoami',
            r3_uri: 'https://rs.example/r3/x',
            // r3_s256 missing
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_resource_token')
    })

    it('grants the proposed operation of a per-call proposal', async function () {
        // R3 -02 §Per-Call Proposals: a proposal is an R3 document with a
        // REQUIRED `parameters` object carrying that call's arguments.
        const r3_uri = 'https://rs.example/r3/proposal-1'
        const proposal = {
            vocabulary: 'urn:aauth:vocabulary:mcp',
            operations: [{ tool: 'send_email' }],
            parameters: {
                to: 'mom@example.com',
                subject: 'Dinner Sunday?',
                body: { s256: 'aBcD', excerpt: 'Hi Mom…', media_type: 'text/plain' },
            },
            display: { summary: 'Send an email as you' },
        }
        const { r3_s256 } = await registerR3Document(fastify, r3_uri, proposal)

        const response = await postToken({ scope: 'whoami', r3_uri, r3_s256 })
        expect(response.statusCode).to.equal(200)
        const claims = decodeJwt(response.json().auth_token)
        expect(claims.r3_s256).to.equal(r3_s256)
        // Approving a proposal grants the one call it describes.
        expect(claims.r3_granted).to.deep.equal({
            vocabulary: proposal.vocabulary,
            operations: proposal.operations,
        })
        expect(claims.r3_per_call).to.be.undefined
    })

    it('rejects a proposal whose parameters is not an object', async function () {
        const r3_uri = 'https://rs.example/r3/proposal-bad'
        const { r3_s256 } = await registerR3Document(fastify, r3_uri, {
            vocabulary: 'urn:aauth:vocabulary:mcp',
            operations: [{ tool: 'send_email' }],
            parameters: ['mom@example.com'],
        })
        const response = await postToken({ scope: 'whoami', r3_uri, r3_s256 })
        expect(response.statusCode).to.equal(400)
        expect(response.json().detail).to.match(/parameters/)
    })

    it('rejects the openapi-gateway vocabulary removed in R3 -02', async function () {
        const r3_uri = 'https://rs.example/r3/gateway'
        const { r3_s256 } = await registerR3Document(fastify, r3_uri, {
            vocabulary: 'urn:aauth:vocabulary:openapi-gateway',
            operations: [{ operationId: 'listNotes' }],
        })
        const response = await postToken({ scope: 'whoami', r3_uri, r3_s256 })
        expect(response.statusCode).to.equal(400)
        expect(response.json().detail).to.match(/openapi-gateway/)
    })
})
