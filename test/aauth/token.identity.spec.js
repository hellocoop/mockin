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
    mintAgentToken,
    mintResourceToken,
    signedRequest,
    DEFAULT_AGENT_ID,
    ephemeralPublicJwk,
    RESOURCE_SERVER_URL,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('AAuth /aauth/token — identity flow (no R3)', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('issues a verifiable auth_token in auto-approve mode', async function () {
        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({
            scope: 'openid email whoami',
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
        const data = response.json()
        expect(data.auth_token).to.be.a('string')
        expect(data.expires_in).to.equal(3600)

        const header = decodeProtectedHeader(data.auth_token)
        expect(header.alg).to.equal('EdDSA')
        expect(header.typ).to.equal('aa-auth+jwt')
        expect(header.kid).to.be.a('string')

        const claims = decodeJwt(data.auth_token)
        expect(claims.iss).to.equal(ISSUER)
        expect(claims.dwk).to.equal('aauth-person.json')
        expect(claims.aud).to.equal(RESOURCE_SERVER_URL)
        expect(claims.sub).to.equal(defaultUser.sub)
        expect(claims.agent).to.equal(DEFAULT_AGENT_ID)
        expect(claims.act).to.deep.equal({ sub: DEFAULT_AGENT_ID })
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
        const jwks = jwksRes.json()
        const localJwks = createLocalJWKSet(jwks)

        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({ scope: 'openid' })

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

        const { payload: verified } = await jwtVerify(
            response.json().auth_token,
            localJwks,
        )
        expect(verified.iss).to.equal(ISSUER)
    })

    it('honours mock token_lifetime override', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ token_lifetime: 60 }),
        })

        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({ scope: 'openid' })
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
        expect(response.json().expires_in).to.equal(60)

        const claims = decodeJwt(response.json().auth_token)
        expect(claims.exp - claims.iat).to.equal(60)
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

        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({ scope: 'openid email' })
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
        const claims = decodeJwt(response.json().auth_token)
        expect(claims.email).to.equal('override@example.com')
        expect(claims.custom).to.equal('value')
    })
})
