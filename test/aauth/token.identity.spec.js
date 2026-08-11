// Non-R3 PS token flow — agent presents a resource_token whose `scope`
// describes identity + resource scopes (whoami-style). The PS issues an
// auth_token with identity claims released and resource scopes passed
// through.

import { expect } from 'chai'
import { decodeProtectedHeader, decodeJwt, jwtVerify, createLocalJWKSet } from 'jose'
import Fastify from 'fastify'

import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import defaultUser from '../../src/users.js'
import {
    installMocks,
    signedRequest,
    personAndResourceToken,
    ephemeralPublicJwk,
    RESOURCE_SERVER_URL,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

// Every token request now starts from a person token: the PS only accepts
// a resource token whose person_token_jti names one it issued.
async function postToken({ person = {}, resource = {}, body = {} } = {}) {
    const { agentToken, resourceToken, personClaims } =
        await personAndResourceToken(fastify, { person, resource })
    const { headers, payload } = await signedRequest({
        method: 'POST',
        path: '/aauth/token',
        body: { resource_token: resourceToken, ...body },
        agentToken,
    })
    const response = await fastify.inject({
        method: 'POST', url: '/aauth/token', headers, payload,
    })
    return { response, personClaims }
}

describe('AAuth /aauth/token — identity flow (no R3)', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('issues a verifiable auth_token in auto-approve mode', async function () {
        const { response, personClaims } = await postToken({
            resource: { scope: 'openid email whoami' },
        })

        expect(response.statusCode).to.equal(200)
        const data = response.json()
        expect(data.auth_token).to.be.a('string')
        expect(data.expires_in).to.equal(3600)

        const header = decodeProtectedHeader(data.auth_token)
        expect(header.alg).to.equal('Ed25519')
        expect(header.typ).to.equal('aa-auth+jwt')
        expect(header.kid).to.be.a('string')

        const claims = decodeJwt(data.auth_token)
        expect(claims.iss).to.equal(ISSUER)
        expect(claims.dwk).to.equal('aauth-person.json')
        expect(claims.aud).to.equal(RESOURCE_SERVER_URL)
        // -11: `ps` REQUIRED, `sub` REQUIRED and equal to the person
        // token's; no `agent` claim and no `act`.
        expect(claims.ps).to.equal(ISSUER)
        expect(claims.sub).to.equal(personClaims.sub)
        expect(claims).to.not.have.property('agent')
        expect(claims).to.not.have.property('act')
        expect(claims.cnf?.jwk).to.deep.include({
            kty: ephemeralPublicJwk.kty,
            crv: ephemeralPublicJwk.crv,
            x: ephemeralPublicJwk.x,
        })
        // identity scopes lifted into named claims; resource scope passes through.
        expect(claims.email).to.equal(defaultUser.email)
        expect(claims.scope).to.equal('whoami')
        expect(claims.r3_uri).to.be.undefined
    })

    it('verifies with the published PS JWKS', async function () {
        const jwksRes = await fastify.inject({
            method: 'GET',
            url: '/aauth/jwks.json',
        })
        const localJwks = createLocalJWKSet(jwksRes.json())

        const { response } = await postToken({ resource: { scope: 'openid' } })
        expect(response.statusCode).to.equal(200)

        const { payload: verified } = await jwtVerify(
            response.json().auth_token,
            localJwks,
            { algorithms: ['Ed25519'] },
        )
        expect(verified.iss).to.equal(ISSUER)
    })

    it('copies mission_s256 and tenant from the resource token', async function () {
        const mission_s256 = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        const { response } = await postToken({
            person: { mission_s256, tenant: 'acme' },
            resource: { scope: 'whoami' },
        })
        expect(response.statusCode).to.equal(200)
        const claims = decodeJwt(response.json().auth_token)
        expect(claims.mission_s256).to.equal(mission_s256)
        expect(claims.tenant).to.equal('acme')
    })

    it('honours mock token_lifetime override', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ token_lifetime: 60 }),
        })

        const { response } = await postToken({ resource: { scope: 'openid' } })
        expect(response.statusCode).to.equal(200)
        expect(response.json().expires_in).to.equal(60)

        const claims = decodeJwt(response.json().auth_token)
        expect(claims.exp - claims.iat).to.equal(60)
    })

    it('caps the auth token lifetime at one hour', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ token_lifetime: 7200 }),
        })
        const { response } = await postToken({ resource: { scope: 'openid' } })
        const claims = decodeJwt(response.json().auth_token)
        expect(claims.exp - claims.iat).to.equal(3600)
    })

    it('honours mock claims override', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                claims: { email: 'override@example.com', custom: 'value' },
            }),
        })

        const { response } = await postToken({
            resource: { scope: 'openid email' },
        })
        const claims = decodeJwt(response.json().auth_token)
        expect(claims.email).to.equal('override@example.com')
        expect(claims.custom).to.equal('value')
    })
})
