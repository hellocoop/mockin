// auth_token_endpoint error paths — bad signatures, mismatched claims, mock
// errors, and the -11 §Resource Token Verification step-6 binding (issue
// #152): the agent presents the token it carried to the resource as
// `presented_token`; it must verify, and the resource token's
// `presented_jti`, `ps`, `sub`, `mission_s256` and `tenant` must match it
// exactly.

import { expect } from 'chai'
import { randomUUID } from 'crypto'
import { SignJWT, decodeJwt } from 'jose'
import Fastify from 'fastify'

import api from '../../src/api.js'
import {
    installMocks,
    mintAgentToken,
    mintResourceToken,
    postAuthToken,
    endpointPath,
    getPersonToken,
    personAndResourceToken,
    resourceServer,
    ephemeralJkt,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

const MISSION_S256 = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

async function postResourceToken(resourceToken, agentToken, presentedToken) {
    const token = agentToken || (await mintAgentToken())
    const body = { resource_token: resourceToken }
    if (presentedToken) body.presented_token = presentedToken
    return postAuthToken(fastify, { body, agentToken: token })
}

describe('AAuth auth_token_endpoint — errors', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('401 + Accept-Signature when no signature is present', async function () {
        const response = await fastify.inject({
            method: 'POST',
            url: await endpointPath(fastify, 'auth_token_endpoint'),
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
        const response = await postResourceToken(resourceToken, tampered, 'x.y.z')
        // The HTTPSig step verifies the HTTP signature using cnf.jwk from
        // the JWT — that still passes because we used the real ephemeral
        // key — and then mockin rejects because the JWT signature itself
        // is invalid.
        expect(response.statusCode).to.equal(401)
        expect(response.json().error).to.equal('invalid_jwt')
    })

    it('returns RFC 9457 problem details, not error_description', async function () {
        const { person_token } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({
            personToken: person_token,
            aud: 'https://wrong-ps.example',
        })
        const response = await postResourceToken(resourceToken, undefined, person_token)
        expect(response.headers['content-type'])
            .to.match(/^application\/problem\+json/)
        const body = response.json()
        expect(body.error).to.equal('invalid_resource_token')
        expect(body.detail).to.be.a('string')
        expect(body).to.not.have.property('error_description')
    })

    it('400 invalid_request when resource_token missing', async function () {
        const agentToken = await mintAgentToken()
        const response = await postAuthToken(fastify, { body: {}, agentToken })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_request')
    })

    it('400 on upstream_token — call chaining is not implemented', async function () {
        const { agentToken, body } = await personAndResourceToken(fastify)
        const response = await postAuthToken(fastify, {
            body: { ...body, upstream_token: 'eyJ.e30.x' },
            agentToken,
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().detail).to.match(/upstream_token/)
    })

    it('400 invalid_resource_token when aud != PS', async function () {
        const { person_token } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({
            personToken: person_token,
            aud: 'https://wrong-ps.example',
        })
        const response = await postResourceToken(resourceToken, undefined, person_token)
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_resource_token')
        expect(response.json().detail).to.match(/aud/)
    })

    it('400 invalid_resource_token when agent_jkt mismatches HTTPSig key', async function () {
        const { person_token } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({
            personToken: person_token,
            agent_jkt: 'wrongthumbprint',
        })
        const response = await postResourceToken(resourceToken, undefined, person_token)
        expect(response.statusCode).to.equal(400)
        expect(response.json().detail).to.match(/agent_jkt/)
    })

    it('400 expired_resource_token when the resource token has expired', async function () {
        const { person_token } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({
            personToken: person_token,
            ttl: -60,
        })
        const response = await postResourceToken(resourceToken, undefined, person_token)
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('expired_resource_token')
    })

    describe('presented token binding (§Resource Token Verification step 6)', function () {
        it('rejects a resource token with no presented_jti', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                person_token_jti: false,
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(400)
            expect(response.json().detail).to.match(/presented_jti/)
        })

        it('400 invalid_request when presented_token is missing', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({ presentedToken: person_token })
            const response = await postResourceToken(resourceToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error).to.equal('invalid_request')
            expect(response.json().detail).to.match(/presented_token/)
        })

        it('accepts the renamed presented_jti claim alone (spec issue #95)', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                jti_claim: 'presented',
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(200)
        })

        it('accepts the legacy person_token_jti claim alone', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                jti_claim: 'legacy',
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(200)
        })

        it('rejects a presented_jti that does not name the presented token', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                person_token_jti: randomUUID(),
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error).to.equal('invalid_resource_token')
            expect(response.json().detail).to.match(/does not name the presented token/)
        })

        it('rejects a presented token that is not a person or auth token', async function () {
            const { person_token, agentToken } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({ presentedToken: person_token })
            const response = await postResourceToken(resourceToken, agentToken, agentToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error).to.equal('invalid_presented_token')
            expect(response.json().detail).to.match(/typ/)
        })

        it('rejects a presented token this PS did not sign', async function () {
            const { person_token, claims } = await getPersonToken(fastify)
            // Same claims, signed by the resource server's key.
            const forged = await new SignJWT(claims)
                .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-person+jwt', kid: 'not-ours' })
                .sign(resourceServer.privateKey)
            const resourceToken = await mintResourceToken({ presentedToken: person_token })
            const response = await postResourceToken(resourceToken, undefined, forged)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error).to.equal('invalid_presented_token')
            expect(response.json().detail).to.match(/signature/)
        })

        it('rejects an expired presented token with expired_presented_token', async function () {
            const { person_token, claims } = await getPersonToken(fastify)
            const { privateJwk } = await import('../../src/aauth/keys.js')
            const { importJWK } = await import('jose')
            const key = await importJWK(privateJwk, 'Ed25519')
            const stale = await new SignJWT({ ...claims, iat: claims.iat - 7200, exp: claims.iat - 3600 })
                .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-person+jwt', kid: privateJwk.kid })
                .sign(key)
            const resourceToken = await mintResourceToken({ presentedToken: person_token })
            const response = await postResourceToken(resourceToken, undefined, stale)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error).to.equal('expired_presented_token')
        })

        it('rejects a presented token for another resource (aud)', async function () {
            const { person_token } = await getPersonToken(fastify, {
                resource: 'https://other.example',
            })
            // The resource token is rs.example's, but the person token
            // names other.example.
            const resourceToken = await mintResourceToken({ presentedToken: person_token })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error).to.equal('invalid_presented_token')
            expect(response.json().detail).to.match(/aud/)
        })

        it('rejects a presented token bound to another agent key (cnf ≠ agent_jkt)', async function () {
            const { generateKeyPair, exportJWK, calculateJwkThumbprint } = await import('jose')
            const other = await generateKeyPair('Ed25519', { extractable: true })
            const otherJwk = await exportJWK(other.publicKey)
            otherJwk.alg = 'Ed25519'
            // A person token bound to a different agent key.
            const otherAgentToken = await mintAgentToken({ cnf_jwk: otherJwk })
            const otherPrivate = await exportJWK(other.privateKey)
            otherPrivate.alg = 'Ed25519'
            const { signedRequest } = await import('./helpers.js')
            const path = await endpointPath(fastify, 'person_token_endpoint')
            const { headers, payload } = await signedRequest({
                method: 'POST', path, body: { resource: 'https://rs.example' },
                agentToken: otherAgentToken, signingKey: otherPrivate,
            })
            const ptRes = await fastify.inject({ method: 'POST', url: path, headers, payload })
            expect(ptRes.statusCode).to.equal(200)
            const otherPersonToken = ptRes.json().person_token
            // The resource token binds OUR ephemeral key; the presented
            // token was issued to the other key.
            const resourceToken = await mintResourceToken({
                presentedToken: otherPersonToken,
                agent_jkt: ephemeralJkt,
            })
            const response = await postResourceToken(resourceToken, undefined, otherPersonToken)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error).to.equal('invalid_presented_token')
            expect(response.json().detail).to.match(/agent_jkt/)
            void calculateJwkThumbprint
        })

        it('rejects a mismatched sub', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                sub: 'some-other-subject',
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(400)
            expect(response.json().error).to.equal('invalid_resource_token')
            expect(response.json().detail).to.match(/sub mismatch/)
        })

        it('rejects a mismatched ps', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                ps: 'https://other-ps.example',
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(400)
            expect(response.json().detail).to.match(/ps mismatch/)
        })

        it('rejects a stripped mission_s256', async function () {
            // The mission-stripping case this binding exists to catch: the
            // person token carried a mission, the resource token dropped it.
            const { person_token } = await getPersonToken(fastify, {
                mission_s256: MISSION_S256,
            })
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                mission_s256: false, // falsy → omitted from the token
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(400)
            expect(response.json().detail).to.match(/mission_s256 mismatch/)
        })

        it('rejects an invented mission_s256', async function () {
            const { person_token } = await getPersonToken(fastify)
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                mission_s256: MISSION_S256,
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(400)
            expect(response.json().detail).to.match(/mission_s256 mismatch/)
        })

        it('rejects a mismatched tenant', async function () {
            const { person_token } = await getPersonToken(fastify, { tenant: 'acme' })
            const resourceToken = await mintResourceToken({
                presentedToken: person_token,
                tenant: 'globex',
            })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(400)
            expect(response.json().detail).to.match(/tenant mismatch/)
        })

        it('accepts the matching set, mission and tenant included', async function () {
            const { person_token } = await getPersonToken(fastify, {
                mission_s256: MISSION_S256,
                tenant: 'acme',
            })
            const resourceToken = await mintResourceToken({ presentedToken: person_token })
            const response = await postResourceToken(resourceToken, undefined, person_token)
            expect(response.statusCode).to.equal(200)
        })

        it('reuses one person token across resource tokens', async function () {
            const { person_token } = await getPersonToken(fastify)
            for (let i = 0; i < 2; i++) {
                const resourceToken = await mintResourceToken({ presentedToken: person_token })
                const response = await postResourceToken(resourceToken, undefined, person_token)
                expect(response.statusCode).to.equal(200)
            }
        })

        it('step-up: accepts a resource token naming the auth token the agent carried', async function () {
            const { person_token, agentToken } = await getPersonToken(fastify)
            const first = await postResourceToken(
                await mintResourceToken({ presentedToken: person_token }),
                agentToken, person_token,
            )
            expect(first.statusCode).to.equal(200)
            const authToken = first.json().auth_token
            const auth = decodeJwt(authToken)
            expect(auth.jti).to.be.a('string')

            // The resource challenged again on a request carrying the auth
            // token: presented_jti names it, ps/sub copied from it, and the
            // agent presents the auth token.
            const stepUpRt = await mintResourceToken({ presentedToken: authToken })
            expect(decodeJwt(stepUpRt).presented_jti).to.equal(auth.jti)
            expect(decodeJwt(stepUpRt).ps).to.equal(auth.ps)
            const stepUp = await postResourceToken(stepUpRt, agentToken, authToken)
            expect(stepUp.statusCode).to.equal(200)
            const issued = decodeJwt(stepUp.json().auth_token)
            expect(issued.sub).to.equal(auth.sub)
            // §Auth Token Structure: never past the presented token's exp.
            expect(issued.exp).to.be.at.most(auth.exp)
        })

        it('caps the auth token at the presented token exp', async function () {
            const { person_token, claims } = await getPersonToken(fastify)
            const { privateJwk } = await import('../../src/aauth/keys.js')
            const { importJWK } = await import('jose')
            const key = await importJWK(privateJwk, 'Ed25519')
            const now = Math.floor(Date.now() / 1000)
            const shortLived = await new SignJWT({ ...claims, iat: now, exp: now + 120 })
                .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-person+jwt', kid: privateJwk.kid })
                .sign(key)
            const resourceToken = await mintResourceToken({ presentedToken: shortLived })
            const response = await postResourceToken(resourceToken, undefined, shortLived)
            expect(response.statusCode).to.equal(200)
            expect(response.json().expires_in).to.be.at.most(120)
            expect(decodeJwt(response.json().auth_token).exp).to.be.at.most(now + 120)
            void person_token
        })
    })
})
