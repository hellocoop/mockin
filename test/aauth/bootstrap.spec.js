// Bootstrap endpoint — uses HWK scheme (raw ephemeral key), not JWT.
//
// Per spec the PS replies 202 + AAuth-Requirement: requirement=interaction;
// url; code, with Location pointing at the pending URL. The agent directs
// the user to {url}?code=...&callback=..., the user approves, and a poll
// of the pending URL returns the bootstrap_token.
//
// In auto-approve mode (default) mockin pre-marks the pending entry as
// approved so the very first poll returns the token without any consent
// redirect — useful for testing.

import { expect } from 'chai'
import {
    decodeProtectedHeader, decodeJwt, jwtVerify, createLocalJWKSet, calculateJwkThumbprint,
} from 'jose'
import Fastify from 'fastify'

import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import {
    installMocks,
    signedHwkRequest,
    ephemeralPublicJwk,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('AAuth /aauth/bootstrap', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('202 + AAuth-Requirement on POST /aauth/bootstrap', async function () {
        const { headers, payload } = await signedHwkRequest({
            method: 'POST',
            path: '/aauth/bootstrap',
            body: { agent_server: 'https://as.example' },
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(202)
        expect(response.headers.location).to.match(/\/aauth\/pending\//)
        expect(response.headers['aauth-requirement']).to.match(
            /^requirement=interaction;\s*url=".+";\s*code="[A-Za-z0-9]+"$/,
        )
        expect(response.json()).to.include.keys('status', 'location', 'code')
        expect(response.json().status).to.equal('pending')
    })

    it('first poll returns bootstrap_token in auto-approve mode', async function () {
        const init = await signedHwkRequest({
            method: 'POST',
            path: '/aauth/bootstrap',
            body: { agent_server: 'https://as.example' },
        })
        const initRes = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers: init.headers,
            payload: init.payload,
        })
        expect(initRes.statusCode).to.equal(202)

        const path = new URL(initRes.headers.location).pathname
        const { headers: pollHeaders } = await signedHwkRequest({
            method: 'GET',
            path,
        })
        const poll = await fastify.inject({
            method: 'GET',
            url: path,
            headers: pollHeaders,
        })
        expect(poll.statusCode).to.equal(200)
        const data = poll.json()
        expect(data.bootstrap_token).to.be.a('string')
        expect(data.expires_in).to.be.a('number')

        const header = decodeProtectedHeader(data.bootstrap_token)
        expect(header.typ).to.equal('aa-bootstrap+jwt')

        const claims = decodeJwt(data.bootstrap_token)
        expect(claims.iss).to.equal(ISSUER)
        expect(claims.aud).to.equal('https://as.example')
        expect(claims.cnf?.jwk?.x).to.equal(ephemeralPublicJwk.x)

        const jwks = (
            await fastify.inject({ method: 'GET', url: '/aauth/jwks.json' })
        ).json()
        const verified = await jwtVerify(
            data.bootstrap_token,
            createLocalJWKSet(jwks),
        )
        expect(verified.payload.iss).to.equal(ISSUER)
    })

    it('cnf.jwk thumbprint matches the HTTPSig key', async function () {
        const init = await signedHwkRequest({
            method: 'POST',
            path: '/aauth/bootstrap',
            body: { agent_server: 'https://as.example' },
        })
        const initRes = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers: init.headers,
            payload: init.payload,
        })
        const path = new URL(initRes.headers.location).pathname
        const { headers: pollHeaders } = await signedHwkRequest({
            method: 'GET',
            path,
        })
        const poll = await fastify.inject({
            method: 'GET',
            url: path,
            headers: pollHeaders,
        })
        const claims = decodeJwt(poll.json().bootstrap_token)
        const jkt = await calculateJwkThumbprint(claims.cnf.jwk)
        const epJkt = await calculateJwkThumbprint(ephemeralPublicJwk)
        expect(jkt).to.equal(epJkt)
    })

    it('consent endpoint approves a pending bootstrap and redirects', async function () {
        // Disable auto_approve so consent must drive the approval.
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ auto_approve: false }),
        })

        const init = await signedHwkRequest({
            method: 'POST',
            path: '/aauth/bootstrap',
            body: { agent_server: 'https://as.example' },
        })
        const initRes = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers: init.headers,
            payload: init.payload,
        })
        const code = initRes.json().code
        const path = new URL(initRes.headers.location).pathname

        // Pre-consent poll → 202 still pending.
        const { headers: prePollHeaders } = await signedHwkRequest({
            method: 'GET',
            path,
        })
        const pre = await fastify.inject({
            method: 'GET',
            url: path,
            headers: prePollHeaders,
        })
        expect(pre.statusCode).to.equal(202)

        // User hits consent endpoint with callback.
        const callback = 'https://agent.example.com/return'
        const consent = await fastify.inject({
            method: 'GET',
            url: `/aauth/consent?code=${code}&callback=${encodeURIComponent(callback)}`,
        })
        expect(consent.statusCode).to.equal(302)
        expect(consent.headers.location).to.equal(callback)

        // Post-consent poll → 200 with bootstrap_token.
        const { headers: postPollHeaders } = await signedHwkRequest({
            method: 'GET',
            path,
        })
        const post = await fastify.inject({
            method: 'GET',
            url: path,
            headers: postPollHeaders,
        })
        expect(post.statusCode).to.equal(200)
        expect(post.json().bootstrap_token).to.be.a('string')
    })

    it('accepts a Bootstrap Completion Announcement (sig=jwt) → 204', async function () {
        // Re-import here to keep this test self-contained against the same
        // helpers the token specs use (agent_token signed by mock AS).
        const { mintAgentToken, signedRequest } = await import('./helpers.js')
        const agentToken = await mintAgentToken()
        const { headers, payload } = await signedRequest({
            method: 'POST',
            path: '/aauth/bootstrap',
            body: {},
            agentToken,
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(204)
    })

    it('rejects sig=jwt that is not aa-agent+jwt', async function () {
        // Forge a JWT with the wrong typ.
        const { generateKeyPair, exportJWK, SignJWT } = await import('jose')
        const kp = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
        const pub = await exportJWK(kp.publicKey)
        const ephPrivJwk = await exportJWK(kp.privateKey)
        const wrong = await new SignJWT({
            iss: 'https://wrong.example',
            cnf: { jwk: pub },
        })
            .setProtectedHeader({ alg: 'EdDSA', typ: 'aa-bootstrap+jwt' })
            .setIssuedAt()
            .setExpirationTime('5m')
            .sign(kp.privateKey)

        const { fetch: httpsigFetch } = await import('@hellocoop/httpsig')
        const { ISSUER } = await import('../../src/config.js')
        const { headers: hdrs } = await httpsigFetch(`${ISSUER}/aauth/bootstrap`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{}',
            signingKey: ephPrivJwk,
            signatureKey: { type: 'jwt', jwt: wrong },
            dryRun: true,
        })
        const out = {}
        hdrs.forEach((v, k) => { out[k] = v })
        out.host = new URL(ISSUER).host

        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers: out,
            payload: '{}',
        })
        expect(response.statusCode).to.equal(401)
        expect(response.json().error).to.equal('invalid_jwt')
    })

    it('400 when agent_server missing', async function () {
        const { headers, payload } = await signedHwkRequest({
            method: 'POST',
            path: '/aauth/bootstrap',
            body: {},
        })
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers,
            payload,
        })
        expect(response.statusCode).to.equal(400)
    })

    it('401 when no signature', async function () {
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ agent_server: 'https://as.example' }),
        })
        expect(response.statusCode).to.equal(401)
        expect(response.json().error).to.equal('signature_required')
    })
})
