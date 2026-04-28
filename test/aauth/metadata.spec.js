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
            expect(data.token_endpoint).to.equal(`${ISSUER}/aauth/token`)
            expect(data.permission_endpoint).to.equal(`${ISSUER}/aauth/permission`)
            expect(data.audit_endpoint).to.equal(`${ISSUER}/aauth/audit`)
            expect(data.interaction_endpoint).to.equal(`${ISSUER}/aauth/interaction`)
            expect(data.bootstrap_endpoint).to.equal(`${ISSUER}/aauth/bootstrap`)
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
            expect(key.alg).to.equal('EdDSA')
            expect(key.kid).to.be.a('string')
            expect(key.use).to.equal('sig')
            expect(key).to.not.have.property('d') // private key never exposed
        })
    })
})
