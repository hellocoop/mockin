import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'

const fastify = Fastify()
api(fastify)

describe('AAuth Metadata & JWKS', function () {
    describe('GET /.well-known/aauth-person.json', function () {
        it('publishes PS metadata', async function () {
            const response = await fastify.inject({
                method: 'GET',
                url: '/.well-known/aauth-person.json',
            })
            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.issuer).to.equal(ISSUER)
            expect(data.jwks_uri).to.equal(`${ISSUER}/aauth/jwks.json`)
            // -11 renamed token_endpoint → auth_token_endpoint and made
            // person_token_endpoint REQUIRED of every PS. Both sit under a
            // shared /aauth/token prefix, matching Wallet.
            expect(data.auth_token_endpoint).to.equal(`${ISSUER}/aauth/token/auth`)
            expect(data.person_token_endpoint).to.equal(`${ISSUER}/aauth/token/person`)
            expect(data).to.not.have.property('token_endpoint')
            expect(data.permission_endpoint).to.equal(`${ISSUER}/aauth/permission`)
            expect(data.audit_endpoint).to.equal(`${ISSUER}/aauth/audit`)
            // The person-facing page, not the agent's reach API: an agent
            // composes `{interaction_endpoint}?code=` and sends the person there.
            expect(data.interaction_endpoint).to.equal(`${ISSUER}/aauth/consent`)
            expect(data.reach_endpoint).to.equal(`${ISSUER}/aauth/interaction`)
            expect(data.bootstrap_endpoint).to.equal(`${ISSUER}/aauth/bootstrap`)
        })

        it('serves both token endpoints under the /aauth/token prefix', async function () {
            const data = (await fastify.inject({
                method: 'GET',
                url: '/.well-known/aauth-person.json',
            })).json()
            expect(new URL(data.auth_token_endpoint).pathname)
                .to.equal('/aauth/token/auth')
            expect(new URL(data.person_token_endpoint).pathname)
                .to.equal('/aauth/token/person')
        })

        it('the bare /aauth/token prefix is not an endpoint', async function () {
            // It must not silently route to either of the two, and the 404
            // should say where they actually are.
            for (const method of ['POST', 'GET']) {
                const res = await fastify.inject({
                    method,
                    url: '/aauth/token',
                    headers: { 'content-type': 'application/json' },
                    payload: method === 'POST' ? '{}' : undefined,
                })
                expect(res.statusCode, method).to.equal(404)
                expect(res.headers['content-type'])
                    .to.match(/^application\/problem\+json/)
                const body = res.json()
                expect(body.error).to.equal('not_found')
                expect(body.detail).to.match(/\/aauth\/token\/auth/)
                expect(body.detail).to.match(/\/aauth\/token\/person/)
                expect(body).to.not.have.property('auth_token')
                expect(body).to.not.have.property('person_token')
            }
        })

        it('publishes both token endpoints @aauth/bootstrap 2.0.0 requires', async function () {
            const data = (await fastify.inject({
                method: 'GET',
                url: '/.well-known/aauth-person.json',
            })).json()
            for (const field of ['auth_token_endpoint', 'person_token_endpoint']) {
                expect(data[field], field).to.be.a('string')
            }
        })

        it('sets Cache-Control', async function () {
            const response = await fastify.inject({
                method: 'GET',
                url: '/.well-known/aauth-person.json',
            })
            expect(response.headers['cache-control']).to.match(/max-age/)
        })
    })

    describe('GET /aauth/jwks.json', function () {
        it('returns the PS public key', async function () {
            const response = await fastify.inject({
                method: 'GET',
                url: '/aauth/jwks.json',
            })
            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.keys).to.be.an('array').with.lengthOf(1)
            const key = data.keys[0]
            expect(key.kty).to.equal('OKP')
            expect(key.crv).to.equal('Ed25519')
            expect(key.alg).to.equal('Ed25519')
            expect(key.kid).to.be.a('string')
            expect(key.use).to.equal('sig')
            expect(key).to.not.have.property('d') // private key never exposed
        })
    })
})
