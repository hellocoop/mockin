import { expect } from 'chai'
import pkceChallenge from "pkce-challenge"
import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

import defaultUser from '../src/users.js'
const ISSUER = 'http://mockin'

const { code_challenge, code_verifier } = await pkceChallenge()
const client_id = 'client_id-value'
const nonce = 'nonce-value'
const redirect_uri = 'https://redirect_uri-value'

describe('Authorize Mock Tests', function() {
    beforeEach(async function() {
        // DELETE /mock
    })
    describe('GET /mock', function() {
        it('should return empty MOCK object', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/mock',
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data).to.exist
            expect(data.MOCK).to.exist
            expect(data.MOCK).to.deep.equal({})
        })
    })
    describe('GET /mock', function() {
        it('should return empty MOCK object', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/mock',
            })
            const { statusCode, body } = response
            console.log({statusCode, body})
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data).to.exist
            expect(data.MOCK).to.exist
            expect(data.MOCK).to.deep.equal({})
        })
    })
})
