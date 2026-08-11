// /aauth/token error paths — bad signatures, mismatched claims, mock
// errors, and the -11 §Resource Token Verification step-6 binding: the
// resource token must name a person token this PS issued, and its `ps`,
// `sub`, `mission_s256` and `tenant` must match that token exactly.

import { expect } from 'chai'
import { randomUUID } from 'crypto'
import Fastify from 'fastify'

import api from '../../src/api.js'
import {
    installMocks,
    mintAgentToken,
    mintResourceToken,
    signedRequest,
    getPersonToken,
    personAndResourceToken,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

const MISSION_S256 = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

async function postResourceToken(resourceToken, agentToken) {
    const token = agentToken || (await mintAgentToken())
    const { headers, payload } = await signedRequest({
        method: 'POST',
        path: '/aauth/token',
        body: { resource_token: resourceToken },
        agentToken: token,
    })
    return fastify.inject({
        method: 'POST', url: '/aauth/token', headers, payload,
    })
}

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
        // -11: the body signature must cover content-digest and content-type.
        expect(response.headers['accept-signature']).to.match(/content-digest/)
        expect(response.json().error).to.equal('signature_required')
    })

    it('401 invalid_jwt when agent_token signature is bad', async function () {
        // Mint a token then corrupt its signature (last segment).
        const real = await mintAgentToken()
        const segs = real.split('.')
        segs[2] = 'AAAAAAAAAAAAAAAAAAAAAA'
        const tampered = segs.join('.')

        const resourceToken = await mintResourceToken({
            scope: 'openid', sub: 'x', person_token_jti: 'y',
        })
        const response = await postResourceToken(resourceToken, tampered)
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

    it('400 on upstream_token — call chaining is not implemented', async function () {
        const { agentToken, resourceToken } = await personAndResourceToken(fastify)
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/token',
            body: { resource_token: resourceToken, upstream_token: 'eyJ.e30.x' },
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST', url: '/aauth/token', headers, payload,
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error_description).to.match(/upstream_token/)
    })

    it('400 invalid_resource_token when aud != PS', async function () {
        const { person_token } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({
            personToken: person_token,
            aud: 'https://wrong-ps.example',
        })
        const response = await postResourceToken(resourceToken)
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_resource_token')
        expect(response.json().error_description).to.match(/aud/)
    })

    it('400 invalid_resource_token when agent_jkt mismatches HTTPSig key', async function () {
        const { person_token } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({
            personToken: person_token,
            agent_jkt: 'wrongthumbprint',
        })
        const response = await postResourceToken(resourceToken)
        expect(response.statusCode).to.equal(400)
        expect(response.json().error_description).to.match(/agent_jkt/)
    })

    it('400 expired_resource_token when the resource token has expired', async function () {
        const { person_token } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({
            personToken: person_token,
            ttl: -60,
        })
        const response = await postResourceToken(resourceToken)
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('expired_resource_token')
    })

    describe('person token binding (§Resource Token Verification step 6)', function () {
        it('rejects a resource token with no person_token_jti', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                personToken: person_token,
                person_token_jti: false,
            })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error_description).to.match(/person_token_jti/)
        })

        it('rejects a person_token_jti this PS never issued', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                personToken: person_token,
                person_token_jti: randomUUID(),
            })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error_description)
                .to.match(/names no person token this PS issued/)
        })

        it('rejects a mismatched sub', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                personToken: person_token,
                sub: 'some-other-subject',
            })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error_description).to.match(/sub mismatch/)
        })

        it('rejects a mismatched ps', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                personToken: person_token,
                ps: 'https://other-ps.example',
            })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error_description).to.match(/ps mismatch/)
        })

        it('rejects a stripped mission_s256', async function () {
            // The mission-stripping case this binding exists to catch: the
            // person token carried a mission, the resource token dropped it.
            const { person_token } = await getPersonToken(fastify, {
                mission_s256: MISSION_S256,
            })
            const resourceToken = await mintResourceToken({
                personToken: person_token,
                mission_s256: false, // falsy → omitted from the token
            })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error_description).to.match(/mission_s256 mismatch/)
        })

        it('rejects an invented mission_s256', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                personToken: person_token,
                mission_s256: MISSION_S256,
            })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error_description).to.match(/mission_s256 mismatch/)
        })

        it('rejects a mismatched tenant', async function () {
            const { person_token } = await getPersonToken(fastify, { tenant: 'acme' })
            const resourceToken = await mintResourceToken({
                personToken: person_token,
                tenant: 'globex',
            })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error_description).to.match(/tenant mismatch/)
        })

        it('accepts the matching set, mission and tenant included', async function () {
            const { person_token } = await getPersonToken(fastify, {
                mission_s256: MISSION_S256,
                tenant: 'acme',
            })
            const resourceToken = await mintResourceToken({ personToken: person_token })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(200)
        })
    })

    it('rejects a resource token signed with the polymorphic EdDSA', async function () {
        // -10: implementations MUST NOT accept `EdDSA`. Re-sign the header
        // is not possible without the resource key, so mint via the helper
        // and swap the header — the alg check runs before signature
        // verification, so the error names the algorithm.
        const { person_token } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({ personToken: person_token })
        const [, body, sig] = resourceToken.split('.')
        const header = Buffer.from(
            JSON.stringify({ alg: 'EdDSA', typ: 'aa-resource+jwt', kid: 'rs-key-1' }),
        ).toString('base64url')
        const response = await postResourceToken(`${header}.${body}.${sig}`)
        expect(response.statusCode).to.equal(400)
        expect(response.json().error_description).to.match(/EdDSA/)
    })

    it('returns mock-injected error code', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ error: 'denied' }),
        })

        const resourceToken = await mintResourceToken({ scope: 'openid' })
        const response = await postResourceToken(resourceToken)
        expect(response.statusCode).to.equal(403)
        expect(response.json().error).to.equal('denied')
    })

    it('scopes mock error to a specific endpoint', async function () {
        const { agentToken, resourceToken } = await personAndResourceToken(fastify)
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                error: 'denied',
                error_endpoint: 'permission',
            }),
        })

        const response = await postResourceToken(resourceToken, agentToken)
        // Token endpoint not impacted; permission endpoint would be.
        expect(response.statusCode).to.equal(200)
    })
})
