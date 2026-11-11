// Key discovery through the shared @hellocoop/httpsig key resolver
// (src/aauth/key-resolver.js): the token-issuer lookup in entity-cache.js
// and the jwks_uri scheme inside httpsig verify() use one resolver, and
// every metadata or JWKS fetch it makes is logged as aauth.mockin.key_fetch.
//
// globalThis.fetch is stubbed: no listening port, no network. The signer is
// on plain http, as the test servers mockin talks to are.

import { expect } from 'chai'
import { generateKeyPair, exportJWK } from 'jose'
import { fetch as httpsigFetch } from '@hellocoop/httpsig'
import Fastify from 'fastify'

import api from '../../src/api.js'
import { getEntity, AGENT_DWK } from '../../src/aauth/entity-cache.js'
import { _resetKeyResolver } from '../../src/aauth/key-resolver.js'
import { resetConfig, setConfig } from '../../src/aauth/mock.js'
import { PS_BODY_COMPONENTS } from './helpers.js'

const SIGNER = 'http://agent.key-resolver.test'
const METADATA_URL = `${SIGNER}/.well-known/${AGENT_DWK}`
const JWKS_URL = `${SIGNER}/jwks.json`

const jwk = (kid) => ({ kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519', x: 'AAAA', kid })

const json = (body) =>
    new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
    })

describe('aauth/key-resolver — signer key discovery', function () {
    const realFetch = globalThis.fetch
    const realLog = console.log
    const realWarn = console.warn
    let served, fetched, events

    beforeEach(function () {
        resetConfig()
        _resetKeyResolver()
        served = {
            [METADATA_URL]: { issuer: SIGNER, jwks_uri: JWKS_URL },
            [JWKS_URL]: { keys: [jwk('k1')] },
        }
        fetched = []
        events = []
        globalThis.fetch = async (url) => {
            const u = String(url)
            fetched.push(u)
            if (served[u]) return json(served[u])
            return new Response('not found', { status: 404 })
        }
        // Keep the key_fetch lines; pass anything else through.
        const capture = (stream, real) => (line, ...rest) => {
            if (typeof line === 'string' && line.includes('"aauth.mockin.key_fetch"')) {
                events.push({ stream, ...JSON.parse(line) })
            } else {
                real(line, ...rest)
            }
        }
        console.log = capture('stdout', realLog)
        console.warn = capture('stderr', realWarn)
    })

    afterEach(function () {
        globalThis.fetch = realFetch
        console.log = realLog
        console.warn = realWarn
        _resetKeyResolver()
        resetConfig()
    })

    it('fetches metadata and JWKS once each, one key_fetch event per fetch', async function () {
        const entity = await getEntity(SIGNER, AGENT_DWK, 'k1')
        expect(entity.metadata.jwks_uri).to.equal(JWKS_URL)
        expect(entity.jwks.keys[0].kid).to.equal('k1')
        expect(fetched).to.deep.equal([METADATA_URL, JWKS_URL])

        expect(events).to.have.length(2)
        expect(events[0]).to.include({
            stream: 'stdout',
            level: 30,
            event: 'aauth.mockin.key_fetch',
            url: METADATA_URL,
            doc: 'metadata',
            id: SIGNER,
            dwk: AGENT_DWK,
            kid: 'k1',
            reason: 'cold',
            ok: true,
            status: 200,
        })
        expect(events[0].msg).to.equal(`metadata fetch ok (cold): ${METADATA_URL}`)
        expect(events[0].duration_ms).to.be.a('number')
        expect(events[1]).to.include({ doc: 'jwks', url: JWKS_URL, reason: 'cold', ok: true })

        // Cached: no fetch, no event.
        await getEntity(SIGNER, AGENT_DWK, 'k1')
        expect(fetched).to.have.length(2)
        expect(events).to.have.length(2)
    })

    it('refuses metadata whose issuer does not match, and does not refetch inside the floor', async function () {
        served[METADATA_URL] = { issuer: 'http://someone-else.test', jwks_uri: JWKS_URL }

        let err
        try {
            await getEntity(SIGNER, AGENT_DWK, 'k1')
        } catch (e) {
            err = e
        }
        expect(err?.message).to.include('does not match')
        expect(events).to.have.length(1)
        expect(events[0]).to.include({ stream: 'stderr', level: 40, doc: 'metadata', ok: false })

        // The failed fetch holds the one-minute floor.
        err = undefined
        try {
            await getEntity(SIGNER, AGENT_DWK, 'k1')
        } catch (e) {
            err = e
        }
        expect(err?.message).to.include('does not match')
        expect(fetched).to.deep.equal([METADATA_URL])
    })

    it('refetches once on an unknown kid (key rotation)', async function () {
        _resetKeyResolver({ minRefetchIntervalMs: 0 })
        await getEntity(SIGNER, AGENT_DWK, 'k1')

        served[JWKS_URL] = { keys: [jwk('k2')] }
        const entity = await getEntity(SIGNER, AGENT_DWK, 'k2')
        expect(entity.jwks.keys.map((k) => k.kid)).to.deep.equal(['k2'])
        const jwksEvents = events.filter((e) => e.doc === 'jwks')
        expect(jwksEvents.map((e) => e.reason)).to.deep.equal(['cold', 'unknown_kid'])
    })

    it('answers a trusted_servers entry without a fetch', async function () {
        setConfig({
            trusted_servers: {
                [SIGNER]: { metadata: { name: 'preloaded' }, jwks: { keys: [jwk('k1')] } },
            },
        })
        const entity = await getEntity(SIGNER, AGENT_DWK, 'k1')
        expect(entity.metadata.name).to.equal('preloaded')
        expect(fetched).to.have.length(0)
        expect(events).to.have.length(0)
    })

    it("resolves a sig=jwks_uri request's key through the same resolver", async function () {
        const { publicKey, privateKey } = await generateKeyPair('Ed25519', { extractable: true })
        const publicJwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'Ed25519' }
        const privateJwk = { ...(await exportJWK(privateKey)), kid: 'k1', alg: 'Ed25519' }
        served[JWKS_URL] = { keys: [publicJwk] }

        const body = JSON.stringify({})
        const { headers } = await httpsigFetch('http://test.mockin.local/aauth/bootstrap', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body,
            signingKey: privateJwk,
            signatureKey: { type: 'jwks_uri', id: SIGNER, kid: 'k1', dwk: AGENT_DWK },
            components: PS_BODY_COMPONENTS,
            dryRun: true,
        })
        const out = { host: 'test.mockin.local' }
        headers.forEach((v, k) => { out[k] = v })

        const fastify = Fastify()
        api(fastify)
        const res = await fastify.inject({
            method: 'POST',
            url: '/aauth/bootstrap',
            headers: out,
            payload: body,
        })
        // The signature verified (over plain http, through mockin's resolver);
        // bootstrap then declines the scheme itself.
        expect(res.statusCode).to.equal(401)
        expect(res.json().error).to.equal('invalid_key')
        expect(fetched).to.deep.equal([METADATA_URL, JWKS_URL])
        expect(events.map((e) => [e.doc, e.ok])).to.deep.equal([
            ['metadata', true],
            ['jwks', true],
        ])
    })
})
