// Verify the SET JWT structure and signature against the OIDC JWKS.
// Wallet signs with its RS256 key; mockin reuses the same key (the OIDC
// signing key at /jwks).

import { expect } from 'chai'
import { decodeProtectedHeader, decodeJwt, jwtVerify, createLocalJWKSet } from 'jose'
import Fastify from 'fastify'

import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import { installFetchSink, SINK_URL } from './helpers.js'

const fastify = Fastify()
api(fastify)

const EVENT_CLAIM = 'https://hello.coop/invite/created'

describe('Invite — SET JWT', function () {
    let sink
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
        sink = installFetchSink()
    })
    afterEach(function () {
        sink.restore()
    })

    async function createAndAccept(extra = {}) {
        const create = await fastify.inject({
            method: 'POST',
            url: '/invite',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                email: 'invitee@example.com',
                prompt: 'Join',
                client_id: 'client-xyz',
                events_uri: SINK_URL,
                initiate_login_uri: 'https://app.example.com/init',
                role: 'admin',
                tenant: 'acme',
                state: 's-123',
                ...extra,
            }),
        })
        const inv = create.json().invite
        const accept = await fastify.inject({
            method: 'PUT',
            url: `/invitation/${inv.id}`,
        })
        return { inv, accept: accept.json() }
    }

    it('header is RS256 with kid', async function () {
        const { accept } = await createAndAccept()
        const hdr = decodeProtectedHeader(accept.event)
        expect(hdr.alg).to.equal('RS256')
        expect(hdr.kid).to.be.a('string')
    })

    it('payload carries iss, aud, jti, iat, and the invite/created claim', async function () {
        const { accept } = await createAndAccept()
        const claims = decodeJwt(accept.event)
        expect(claims.iss).to.equal(ISSUER)
        expect(claims.aud).to.equal('client-xyz')
        expect(claims.jti).to.be.a('string')
        expect(claims.iat).to.be.a('number')
        const data = claims[EVENT_CLAIM]
        expect(data).to.be.an('object')
        expect(data.invitee).to.deep.include({ email: 'invitee@example.com' })
        expect(data.invitee.sub).to.be.a('string')
        expect(data.inviter).to.be.a('string')
        expect(data.role).to.equal('admin')
        expect(data.tenant).to.equal('acme')
        expect(data.state).to.equal('s-123')
    })

    it('omits role/tenant/state when not provided', async function () {
        const { accept } = await createAndAccept({
            role: undefined,
            tenant: undefined,
            state: undefined,
        })
        const data = decodeJwt(accept.event)[EVENT_CLAIM]
        expect(data).to.not.have.property('role')
        expect(data).to.not.have.property('tenant')
        expect(data).to.not.have.property('state')
    })

    it('signature verifies against the OIDC JWKS', async function () {
        const { accept } = await createAndAccept()
        const jwksRes = await fastify.inject({ method: 'GET', url: '/jwks' })
        const jwks = createLocalJWKSet(jwksRes.json())
        const { payload } = await jwtVerify(accept.event, jwks)
        expect(payload.iss).to.equal(ISSUER)
    })

    it('captured POST body equals the JWT in the response', async function () {
        const { accept } = await createAndAccept()
        expect(sink.captured).to.have.lengthOf(1)
        expect(sink.captured[0].body).to.equal(accept.event)
    })

    it('no events_uri → JWT returned in body but no fetch made', async function () {
        const { accept } = await createAndAccept({ events_uri: undefined })
        expect(accept.event).to.be.a('string')
        expect(sink.captured).to.have.lengthOf(0)
    })
})
