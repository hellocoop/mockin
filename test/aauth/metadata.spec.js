import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'

const fastify = Fastify()
api(fastify)

describe('AAuth Metadata & JWKS Tests', function () {
    describe('GET /.well-known/aauth-issuer.json', function () {
        it('should return valid AAuth metadata', async function () {
            const response = await fastify.inject({
                method: 'GET',
                url: '/.well-known/aauth-issuer.json',
            })
            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.issuer).to.equal(ISSUER)
            expect(data.token_endpoint).to.equal(`${ISSUER}/aauth/token`)
            expect(data.interaction_endpoint).to.equal(`${ISSUER}/aauth/interaction`)
            expect(data.jwks_uri).to.equal(`${ISSUER}/aauth/jwks`)
            expect(data.signing_algs_supported).to.deep.equal(['EdDSA'])
            expect(data.scopes_supported).to.deep.equal(['openid', 'profile', 'email'])
        })
    })

    describe('GET /aauth/jwks', function () {
        it('should return JWKS with Ed25519 key', async function () {
            const response = await fastify.inject({
                method: 'GET',
                url: '/aauth/jwks',
            })
            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.keys).to.be.an('array').with.lengthOf(1)
            const key = data.keys[0]
            expect(key.kty).to.equal('OKP')
            expect(key.crv).to.equal('Ed25519')
            expect(key.alg).to.equal('EdDSA')
            expect(key.use).to.equal('sig')
            expect(key.kid).to.be.a('string')
            expect(key.x).to.be.a('string')
            expect(key).to.not.have.property('d') // no private key
        })
    })
})
