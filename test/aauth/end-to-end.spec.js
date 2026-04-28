// End-to-end check: mockin issues bootstrap_token with cnf.jwk, then a
// "downstream agent server" verifies an HTTP request signed under sig=jwt
// where the inner JWT is that bootstrap_token. This is the exact step
// that's failing against playground.aauth.dev.
//
// If this test passes, the bootstrap_token format is correct and the
// failure on playground is runtime-specific (workerd vs. Node) or due to
// some unrelated issue inside playground.

import { expect } from 'chai'
import { generateKeyPair, exportJWK, decodeJwt } from 'jose'
import { fetch as httpsigFetch, verify as httpsigVerify } from '@hellocoop/httpsig'
import Fastify from 'fastify'

import api from '../../src/api.js'
import { installMocks, signedHwkRequest } from './helpers.js'

const fastify = Fastify()
api(fastify)

describe('AAuth bootstrap end-to-end', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('bootstrap_token verifies a sig=jwt request the agent signs', async function () {
        // Step 1: simulate the browser's ephemeral key.
        const ephemeralKp = await generateKeyPair('EdDSA', { crv: 'Ed25519' })
        const ephemeralPublicJwk = await exportJWK(ephemeralKp.publicKey)
        // Strip alg the way browser exportKey would not include it.
        delete ephemeralPublicJwk.alg
        const ephemeralPrivateJwk = await exportJWK(ephemeralKp.privateKey)

        // Step 2: hit mockin /aauth/bootstrap with HWK signed by this key.
        // We can't reuse helpers.signedHwkRequest directly because it uses
        // the helpers' built-in ephemeral; but the goal is the same.
        const { headers: postHeaders, payload } = await (async () => {
            const url = `http://test.mockin.local/aauth/bootstrap`
            const { headers } = await httpsigFetch(url, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ agent_server: 'http://agent.example' }),
                signingKey: ephemeralPrivateJwk,
                signatureKey: { type: 'hwk' },
                dryRun: true,
            })
            const out = {}
            headers.forEach((v, k) => { out[k] = v })
            out.host = 'test.mockin.local'
            return { headers: out, payload: JSON.stringify({ agent_server: 'http://agent.example' }) }
        })()

        const initRes = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers: postHeaders,
            payload,
        })
        expect(initRes.statusCode).to.equal(202)

        // Step 3: poll the pending URL with HWK to get the bootstrap_token.
        const path = new URL(initRes.headers.location).pathname
        const pollUrl = `http://test.mockin.local${path}`
        const { headers: pollHeadersHttp } = await httpsigFetch(pollUrl, {
            method: 'GET',
            signingKey: ephemeralPrivateJwk,
            signatureKey: { type: 'hwk' },
            dryRun: true,
        })
        const pollHeaders = {}
        pollHeadersHttp.forEach((v, k) => { pollHeaders[k] = v })
        pollHeaders.host = 'test.mockin.local'

        const pollRes = await fastify.inject({
            method: 'GET',
            url: path,
            headers: pollHeaders,
        })
        expect(pollRes.statusCode).to.equal(200)
        const bootstrapToken = pollRes.json().bootstrap_token
        expect(bootstrapToken).to.be.a('string')

        // Sanity: bootstrap_token's cnf.jwk.x equals our ephemeral public x.
        const claims = decodeJwt(bootstrapToken)
        expect(claims.cnf.jwk.x).to.equal(ephemeralPublicJwk.x)
        expect(claims.cnf.jwk.kty).to.equal('OKP')
        expect(claims.cnf.jwk.crv).to.equal('Ed25519')

        // Step 4: simulate the agent calling /bootstrap/challenge on its
        // own agent server: signed with sig=jwt;jwt=<bootstrap_token>.
        const challengeUrl = `http://agent.example/bootstrap/challenge`
        const { headers: challengeHeadersHttp } = await httpsigFetch(challengeUrl, {
            method: 'POST',
            signingKey: ephemeralPrivateJwk,
            signatureKey: { type: 'jwt', jwt: bootstrapToken },
            components: ['@method', '@authority', '@path', 'signature-key'],
            dryRun: true,
        })

        // Step 5: verify the request the same way the playground server does.
        const verifyResult = await httpsigVerify({
            method: 'POST',
            authority: 'agent.example',
            path: '/bootstrap/challenge',
            query: '',
            headers: challengeHeadersHttp,
            body: '',
        })

        expect(verifyResult.verified, `verify failed: ${verifyResult.error}`)
            .to.equal(true)
        expect(verifyResult.keyType).to.equal('jwt')
        expect(verifyResult.jwt?.payload?.cnf?.jwk?.x).to.equal(
            ephemeralPublicJwk.x,
        )
    })
})
