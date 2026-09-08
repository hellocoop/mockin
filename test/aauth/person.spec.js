// The PS person_token_endpoint (-11 §Person Token Endpoint, interop demo
// profile surface 2). Paths come from the published metadata, the way an
// agent gets them — never hard-coded here.

import { expect } from 'chai'
import {
    decodeProtectedHeader, decodeJwt, jwtVerify, createLocalJWKSet,
    generateKeyPair, exportJWK, calculateJwkThumbprint,
} from 'jose'
import Fastify from 'fastify'

import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import {
    installMocks,
    mintAgentToken,
    signedRequest,
    requestPersonToken,
    getPersonToken,
    postAuthToken,
    endpointPath,
    ephemeralPublicJwk,
    ephemeralJkt,
    RESOURCE_SERVER_URL,
    DEFAULT_AGENT_ID,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

const MISSION_S256 = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

async function setMock(patch) {
    await fastify.inject({
        method: 'PUT',
        url: '/mock/aauth',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify(patch),
    })
}

describe('AAuth person_token_endpoint', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('issues an aa-person+jwt with the -11 claim set', async function () {
        const res = await requestPersonToken(fastify, {
            resource: RESOURCE_SERVER_URL,
        })
        expect(res.statusCode).to.equal(200)
        const { person_token, expires_in } = res.json()
        expect(person_token).to.be.a('string')
        expect(expires_in).to.be.a('number')

        const header = decodeProtectedHeader(person_token)
        expect(header.alg).to.equal('Ed25519')
        expect(header.typ).to.equal('aa-person+jwt')
        expect(header.kid).to.be.a('string')

        const claims = decodeJwt(person_token)
        expect(claims.iss).to.equal(ISSUER)
        expect(claims.dwk).to.equal('aauth-person.json')
        expect(claims.aud).to.equal(RESOURCE_SERVER_URL)
        expect(claims.sub).to.be.a('string')
        expect(claims.jti).to.be.a('string')
        expect(claims.iat).to.be.a('number')
        expect(claims.exp).to.be.a('number')
        expect(claims.cnf?.jwk).to.deep.include({
            kty: ephemeralPublicJwk.kty,
            crv: ephemeralPublicJwk.crv,
            x: ephemeralPublicJwk.x,
            alg: 'Ed25519',
        })
        // "A person token MUST NOT contain scope or account."
        expect(claims).to.not.have.property('scope')
        expect(claims).to.not.have.property('account')
        expect(claims).to.not.have.property('agent')
    })

    it('verifies with the published PS JWKS', async function () {
        const jwks = (await fastify.inject({
            method: 'GET', url: '/aauth/jwks.json',
        })).json()
        const { person_token } = await getPersonToken(fastify)
        const { payload } = await jwtVerify(person_token, createLocalJWKSet(jwks), {
            algorithms: ['Ed25519'],
        })
        expect(payload.iss).to.equal(ISSUER)
    })

    it('sub matches the auth token sub for the same aud', async function () {
        // The single most consequential invariant: two different values
        // make every resource token fail the PS's own step-6 check.
        const { person_token, claims } = await getPersonToken(fastify)
        const { mintResourceToken } = await import('./helpers.js')
        const agentToken = await mintAgentToken()
        const resourceToken = await mintResourceToken({ presentedToken: person_token })
        const res = await postAuthToken(fastify, {
            body: { resource_token: resourceToken, presented_token: person_token },
            agentToken,
        })
        expect(res.statusCode).to.equal(200)
        const auth = decodeJwt(res.json().auth_token)
        expect(auth.sub).to.equal(claims.sub)
        expect(auth.aud).to.equal(claims.aud)
    })

    it('directs sub per resource', async function () {
        const a = await getPersonToken(fastify, { resource: RESOURCE_SERVER_URL })
        const b = await getPersonToken(fastify, { resource: 'https://other.example' })
        expect(a.claims.sub).to.not.equal(b.claims.sub)
        // …and is stable for the same resource.
        const again = await getPersonToken(fastify, { resource: RESOURCE_SERVER_URL })
        expect(again.claims.sub).to.equal(a.claims.sub)
    })

    it('stamps mission_s256 when the request names one', async function () {
        const { claims } = await getPersonToken(fastify, {
            mission_s256: MISSION_S256,
        })
        expect(claims.mission_s256).to.equal(MISSION_S256)
    })

    it('stamps tenant when the agent names one', async function () {
        // AAuth issue #88: the agent naming the tenant is what selects
        // which of a person's contexts the token carries.
        const { claims } = await getPersonToken(fastify, { tenant: 'acme' })
        expect(claims.tenant).to.equal('acme')
    })

    it('caps exp at one hour', async function () {
        await setMock({ token_lifetime: 7200 })
        const agentToken = await mintAgentToken({ ttl: 7200 })
        const { claims } = await getPersonToken(fastify, { agentToken })
        expect(claims.exp - claims.iat).to.equal(3600)
    })

    it('never outlives the presented agent token', async function () {
        const agentToken = await mintAgentToken({ ttl: 120 })
        const { claims } = await getPersonToken(fastify, { agentToken })
        const agentClaims = decodeJwt(agentToken)
        expect(claims.exp).to.be.at.most(agentClaims.exp)
    })

    describe('request validation', function () {
        it('400 when resource is missing', async function () {
            const res = await requestPersonToken(fastify, { resource: null })
            expect(res.statusCode).to.equal(400)
            expect(res.json().error).to.equal('invalid_request')
        })

        it('400 when resource is not a server identifier', async function () {
            for (const bad of [
                'not-a-url',
                'http://rs.example',           // not https
                'https://rs.example/v1',       // path
                'https://rs.example/',         // trailing slash
                'https://RS.example',          // not lowercase
                'https://rs.example?x=1',      // query
            ]) {
                const res = await requestPersonToken(fastify, { resource: bad })
                expect(res.statusCode, bad).to.equal(400)
                expect(res.json().error, bad).to.equal('invalid_request')
            }
        })

        it('400 on upstream_token — call chaining is not implemented', async function () {
            const res = await requestPersonToken(fastify, {
                upstream_token: 'eyJhbGciOiJFZDI1NTE5In0.e30.x',
            })
            expect(res.statusCode).to.equal(400)
            expect(res.json().error).to.equal('invalid_request')
            expect(res.json().detail).to.match(/upstream_token/)
        })

        it('401 when the body signature does not cover content-digest', async function () {
            const agentToken = await mintAgentToken()
            const path = await endpointPath(fastify, 'person_token_endpoint')
            const { headers, payload } = await signedRequest({
                method: 'POST',
                path,
                body: { resource: RESOURCE_SERVER_URL },
                agentToken,
                // httpsig's own default list for a body — no content-digest.
                components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
            })
            const res = await fastify.inject({
                method: 'POST', url: path, headers, payload,
            })
            expect(res.statusCode).to.equal(401)
            expect(res.json().detail).to.match(/content-digest/)
            expect(res.headers['accept-signature']).to.match(/content-digest/)
        })

        it('accepts an uncovered body when require_body_signing is off', async function () {
            await setMock({ require_body_signing: false })
            const agentToken = await mintAgentToken()
            const path = await endpointPath(fastify, 'person_token_endpoint')
            const { headers, payload } = await signedRequest({
                method: 'POST',
                path,
                body: { resource: RESOURCE_SERVER_URL },
                agentToken,
                components: ['@method', '@authority', '@path', 'content-type', 'signature-key'],
            })
            const res = await fastify.inject({
                method: 'POST', url: path, headers, payload,
            })
            expect(res.statusCode).to.equal(200)
        })

        it('401 when the agent token is signed with the polymorphic EdDSA', async function () {
            // -10: implementations MUST NOT accept `EdDSA`, and there is no
            // transition allowance. The key is the same Ed25519 key, so
            // only the alg identifier is wrong.
            const agentToken = await mintAgentToken({ alg: 'EdDSA' })
            const res = await requestPersonToken(fastify, { agentToken })
            expect(res.statusCode).to.equal(401)
            expect(res.json().error).to.equal('invalid_jwt')
            expect(res.json().detail).to.match(/EdDSA/)
        })

        it('401 when no signature is present', async function () {
            const res = await fastify.inject({
                method: 'POST',
                url: await endpointPath(fastify, 'person_token_endpoint'),
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ resource: RESOURCE_SERVER_URL }),
            })
            expect(res.statusCode).to.equal(401)
            expect(res.json().error).to.equal('signature_required')
            expect(res.headers['accept-signature-alg']).to.match(/Ed25519/)
        })

        it('rejects an unknown platform and an over-long device', async function () {
            const bad = await requestPersonToken(fastify, { platform: 'toaster' })
            expect(bad.statusCode).to.equal(400)
            const long = await requestPersonToken(fastify, { device: 'x'.repeat(65) })
            expect(long.statusCode).to.equal(400)
        })

        it('accepts the auth-token endpoint parameter set', async function () {
            const res = await requestPersonToken(fastify, {
                justification: '## Why\nTo read your calendar.',
                login_hint: 'john.smith@example.com',
                domain_hint: 'example.com',
                prompt: 'consent',
                platform: 'desktop',
                device: 'Chrome on macOS',
                capabilities: ['interaction', 'payment', 'teleportation'],
            })
            expect(res.statusCode).to.equal(200)
        })

        it('returns a mock-injected error', async function () {
            await setMock({ error: 'denied', error_endpoint: 'person' })
            const res = await requestPersonToken(fastify)
            expect(res.statusCode).to.equal(403)
            expect(res.json().error).to.equal('denied')
        })
    })

    // -09 adopted RFC 9457 for AAuth error bodies (§Error Response
    // Format). Mockin is the reference PS, so whatever it emits is what
    // clients get written to parse — it emits `detail`, never
    // `error_description`, and never both.
    describe('RFC 9457 error responses', function () {
        const cases = [
            ['no signature', async () => fastify.inject({
                method: 'POST',
                url: await endpointPath(fastify, 'person_token_endpoint'),
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ resource: RESOURCE_SERVER_URL }),
            })],
            ['bad request', () => requestPersonToken(fastify, { resource: 'nope' })],
            ['injected error', async () => {
                await setMock({ error: 'denied', error_endpoint: 'person' })
                return requestPersonToken(fastify)
            }],
            ['unknown pending id', async () => {
                const agentToken = await mintAgentToken()
                const { headers } = await signedRequest({
                    method: 'GET', path: '/aauth/pending/nope', agentToken,
                })
                return fastify.inject({
                    method: 'GET', url: '/aauth/pending/nope', headers,
                })
            }],
            ['bootstrap without agent_server', async () => {
                const { signedHwkRequest } = await import('./helpers.js')
                const { headers, payload } = await signedHwkRequest({
                    method: 'POST', path: '/aauth/bootstrap', body: {},
                })
                return fastify.inject({
                    method: 'POST', url: '/aauth/bootstrap', headers, payload,
                })
            }],
            ['permission without action', async () => {
                const agentToken = await mintAgentToken()
                const { headers, payload } = await signedRequest({
                    method: 'POST', path: '/aauth/permission', body: {}, agentToken,
                })
                return fastify.inject({
                    method: 'POST', url: '/aauth/permission', headers, payload,
                })
            }],
            ['audit without action', async () => {
                const agentToken = await mintAgentToken()
                const { headers, payload } = await signedRequest({
                    method: 'POST', path: '/aauth/audit', body: {}, agentToken,
                })
                return fastify.inject({
                    method: 'POST', url: '/aauth/audit', headers, payload,
                })
            }],
            ['interaction with an unknown type', async () => {
                const agentToken = await mintAgentToken()
                const { headers, payload } = await signedRequest({
                    method: 'POST',
                    path: '/aauth/interaction',
                    body: { type: 'telepathy' },
                    agentToken,
                })
                return fastify.inject({
                    method: 'POST', url: '/aauth/interaction', headers, payload,
                })
            }],
            ['consent without a code', () => fastify.inject({
                method: 'GET', url: '/aauth/consent',
            })],
        ]

        for (const [name, run] of cases) {
            it(`${name}: problem+json with error and detail`, async function () {
                const res = await run()
                expect(res.statusCode).to.be.at.least(400)
                expect(res.headers['content-type'])
                    .to.match(/^application\/problem\+json/)
                const body = res.json()
                expect(body.error).to.be.a('string')
                expect(body).to.not.have.property('error_description')
            })
        }
    })

    describe('sub-agent tokens', function () {
        async function mintSubAgent(parent = DEFAULT_AGENT_ID) {
            const kp = await generateKeyPair('Ed25519', { extractable: true })
            const jwk = await exportJWK(kp.publicKey)
            jwk.alg = 'Ed25519'
            const token = await mintAgentToken({
                sub: 'aauth:subagent@as.example',
                cnf_jwk: jwk,
                parent_agent: parent,
            })
            return { token, jwk, jkt: await calculateJwkThumbprint(jwk) }
        }

        it('binds cnf to the sub-agent key when subagent_token is presented', async function () {
            const sub = await mintSubAgent()
            const res = await requestPersonToken(fastify, {
                subagent_token: sub.token,
            })
            expect(res.statusCode).to.equal(200)
            const claims = decodeJwt(res.json().person_token)
            expect(claims.cnf.jwk.x).to.equal(sub.jwk.x)
            expect(claims.cnf.jwk.x).to.not.equal(ephemeralPublicJwk.x)
        })

        it('completes surface 5: sub-agent person token → resource token → auth token', async function () {
            const sub = await mintSubAgent()
            const { mintResourceToken } = await import('./helpers.js')

            // 1. The parent obtains a person token bound to the sub-agent's key.
            const ptRes = await requestPersonToken(fastify, { subagent_token: sub.token })
            expect(ptRes.statusCode).to.equal(200)
            const person_token = ptRes.json().person_token

            // 2. The resource issues a resource token bound to the
            //    sub-agent's key (agent_jkt = its thumbprint).
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                agent_jkt: sub.jkt,
            })

            // 3. The parent presents all three to the auth token endpoint:
            //    the resource token, the token the sub-agent presented to
            //    the resource, and the sub-agent's agent token.
            const agentToken = await mintAgentToken()
            const res = await postAuthToken(fastify, {
                body: {
                    resource_token: resourceToken,
                    presented_token: person_token,
                    subagent_token: sub.token,
                },
                agentToken,
            })
            expect(res.statusCode).to.equal(200)
            // 4. The auth token binds the sub-agent's key, not the parent's.
            const claims = decodeJwt(res.json().auth_token)
            expect(claims.cnf.jwk.x).to.equal(sub.jwk.x)
            expect(claims.sub).to.equal(decodeJwt(person_token).sub)
        })

        it('rejects a subagent_token whose parent_agent is not the signer', async function () {
            const sub = await mintSubAgent('aauth:someone-else@as.example')
            const res = await requestPersonToken(fastify, {
                subagent_token: sub.token,
            })
            expect(res.statusCode).to.equal(400)
            expect(res.json().error).to.equal('invalid_agent_token')
            expect(res.json().detail).to.match(/parent_agent/)
        })
    })

    describe('deferred consent path', function () {
        it('202 + AAuth-Requirement, then poll → person_token', async function () {
            await setMock({ person_requirement: 'interaction' })

            const agentToken = await mintAgentToken()
            const init = await requestPersonToken(fastify, { agentToken })
            expect(init.statusCode).to.equal(202)
            expect(init.headers.location).to.match(/\/aauth\/pending\//)
            expect(init.headers['retry-after']).to.be.a('string')
            expect(init.headers['cache-control']).to.equal('no-store')
            const requirement = init.headers['aauth-requirement']
            expect(requirement).to.match(/requirement=interaction/)
            expect(requirement).to.match(/url="/)
            expect(requirement).to.match(/code="/)

            const path = new URL(init.headers.location).pathname
            const { headers: pollHeaders } = await signedRequest({
                method: 'GET', path, agentToken,
            })
            const poll = await fastify.inject({
                method: 'GET', url: path, headers: pollHeaders,
            })
            expect(poll.statusCode).to.equal(200)
            const claims = decodeJwt(poll.json().person_token)
            expect(claims.aud).to.equal(RESOURCE_SERVER_URL)
            expect(claims.cnf.jwk.x).to.equal(ephemeralPublicJwk.x)
        })

        it('drives the full interaction when auto_approve is off', async function () {
            await setMock({ person_requirement: 'interaction', auto_approve: false })

            const agentToken = await mintAgentToken()
            const init = await requestPersonToken(fastify, { agentToken })
            expect(init.statusCode).to.equal(202)
            const code = /code="([^"]+)"/.exec(init.headers['aauth-requirement'])[1]
            const path = new URL(init.headers.location).pathname

            // Poll before consent: still pending.
            const { headers: pollHeaders } = await signedRequest({
                method: 'GET', path, agentToken,
            })
            const early = await fastify.inject({
                method: 'GET', url: path, headers: pollHeaders,
            })
            expect(early.statusCode).to.equal(202)
            expect(early.json().status).to.equal('pending')

            // The person visits the consent URL with the code.
            const consent = await fastify.inject({
                method: 'GET', url: `/aauth/consent?code=${encodeURIComponent(code)}`,
            })
            expect(consent.statusCode).to.equal(200)

            const done = await fastify.inject({
                method: 'GET', url: path, headers: pollHeaders,
            })
            expect(done.statusCode).to.equal(200)
            expect(done.json().person_token).to.be.a('string')
        })

        it('mission_s256 survives the deferred round trip', async function () {
            await setMock({ person_requirement: 'interaction' })
            const agentToken = await mintAgentToken()
            const init = await requestPersonToken(fastify, {
                agentToken, mission_s256: MISSION_S256,
            })
            const path = new URL(init.headers.location).pathname
            const { headers: pollHeaders } = await signedRequest({
                method: 'GET', path, agentToken,
            })
            const poll = await fastify.inject({
                method: 'GET', url: path, headers: pollHeaders,
            })
            expect(decodeJwt(poll.json().person_token).mission_s256)
                .to.equal(MISSION_S256)
        })

        it('403 user_unreachable when the agent cannot drive an interaction', async function () {
            // AAuth issue #89: the agent says what it can handle via
            // `capabilities`; a 202 it cannot complete is not an answer.
            await setMock({ person_requirement: 'interaction' })
            const res = await requestPersonToken(fastify, {
                capabilities: ['payment'],
            })
            expect(res.statusCode).to.equal(403)
            expect(res.json().error).to.equal('user_unreachable')
        })

        it('defers when the agent declares the interaction capability', async function () {
            await setMock({ person_requirement: 'interaction' })
            const res = await requestPersonToken(fastify, {
                capabilities: ['interaction'],
            })
            expect(res.statusCode).to.equal(202)
        })
    })

    describe('the jti store', function () {
        it('records the issued token under its jti', async function () {
            const { claims } = await getPersonToken(fastify, {
                mission_s256: MISSION_S256,
                tenant: 'acme',
            })
            const { getPersonToken: lookup } =
                await import('../../src/aauth/person-token-store.js')
            const record = lookup(claims.jti)
            expect(record).to.not.be.null
            expect(record.ps).to.equal(ISSUER)
            expect(record.sub).to.equal(claims.sub)
            expect(record.aud).to.equal(RESOURCE_SERVER_URL)
            expect(record.mission_s256).to.equal(MISSION_S256)
            expect(record.tenant).to.equal('acme')
            expect(record.exp).to.equal(claims.exp)
        })

        it('drops expired records', async function () {
            const store = await import('../../src/aauth/person-token-store.js')
            store.recordPersonToken({
                jti: 'stale', ps: ISSUER, sub: 'x', aud: RESOURCE_SERVER_URL,
                exp: Math.floor(Date.now() / 1000) - 1,
            })
            expect(store.getPersonToken('stale')).to.be.null
        })

        it('is cleared by DELETE /mock', async function () {
            const { claims } = await getPersonToken(fastify)
            await fastify.inject({ method: 'DELETE', url: '/mock' })
            const { getPersonToken: lookup } =
                await import('../../src/aauth/person-token-store.js')
            expect(lookup(claims.jti)).to.be.null
        })
    })

    it('binds agent_jkt through to the resource token', async function () {
        // Surface 2: the resource copies ps/sub/jti and binds its own
        // token to the key that signed its request.
        const { claims } = await getPersonToken(fastify)
        expect(await calculateJwkThumbprint(claims.cnf.jwk)).to.equal(ephemeralJkt)
    })
})
