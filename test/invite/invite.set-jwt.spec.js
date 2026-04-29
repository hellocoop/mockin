// Verify the SET JWT structure and signature against the OIDC JWKS.
// Wallet signs with its RS256 key; mockin reuses the same key (the OIDC
// signing key at /jwks). The JWT is read from the captured POST body of
// the events_uri webhook — the response from PUT /invitation/:id matches
// wallet (just `{ initiate_login_url }`) and does NOT carry the SET.

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
        return { inv, accept: accept.json(), jwt: sink.captured[0]?.body }
    }

    it('header is RS256 with kid', async function () {
        const { jwt } = await createAndAccept()
        const hdr = decodeProtectedHeader(jwt)
        expect(hdr.alg).to.equal('RS256')
        expect(hdr.kid).to.be.a('string')
    })

    it('payload carries iss, aud, jti, iat, and the invite/created claim', async function () {
        const { jwt } = await createAndAccept()
        const claims = decodeJwt(jwt)
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
        const { jwt } = await createAndAccept({
            role: undefined,
            tenant: undefined,
            state: undefined,
        })
        const data = decodeJwt(jwt)[EVENT_CLAIM]
        expect(data).to.not.have.property('role')
        expect(data).to.not.have.property('tenant')
        expect(data).to.not.have.property('state')
    })

    it('signature verifies against the OIDC JWKS', async function () {
        const { jwt } = await createAndAccept()
        const jwksRes = await fastify.inject({ method: 'GET', url: '/jwks' })
        const jwks = createLocalJWKSet(jwksRes.json())
        const { payload } = await jwtVerify(jwt, jwks)
        expect(payload.iss).to.equal(ISSUER)
    })

    it('PUT /invitation/:id response body matches wallet (no extra fields)', async function () {
        const { accept } = await createAndAccept()
        expect(accept).to.have.all.keys('initiate_login_url')
    })

    it('without events_uri the SET is silently skipped (no fetch made)', async function () {
        const { jwt } = await createAndAccept({ events_uri: undefined })
        expect(jwt).to.be.undefined
        expect(sink.captured).to.have.lengthOf(0)
    })
})
