import { expect } from 'chai'
import pkceChallenge from "pkce-challenge"
import jwt from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

import defaultUser from '../src/users.js'
import { ISSUER } from '../src/config.js'

const { code_challenge, code_verifier } = await pkceChallenge()
const client_id = 'client_id-value'
const nonce = 'nonce-value'
const redirect_uri = 'https://redirect_uri-value'

describe('Authorize Error Tests', function() {
    describe('Missing redirect_uri', function() {
        it('should fail', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    response_type: 'id_token',
                    scope: 'openid',
                })
            })
            expect(response.statusCode).to.equal(400)
            const data = await response.json()
            expect(data).to.exist
            expect(data.error).to.equal('invalid_request')
            expect(data.error_description).to.equal('missing redirect_uri')
        })
    })
    describe('Missing client_id', function() {
        it('should fail', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    nonce,
                    redirect_uri,
                    response_type: 'id_token',
                    scope: 'openid',
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.exist
            expect(error).to.equal('invalid_request')
            const error_description = responseURL.searchParams.get('error_description')
            expect(error_description).to.exist
            expect(error_description).to.equal('missing client_id')
        })
    })
    describe('Missing nonce', function() {
        it('should fail', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    redirect_uri,
                    response_type: 'id_token',
                    scope: 'openid',
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.exist
            expect(error).to.equal('invalid_request')
            const error_description = responseURL.searchParams.get('error_description')
            expect(error_description).to.exist
            expect(error_description).to.equal('missing nonce')            
        })
    })
    describe('Missing scope', function() {
        it('should fail', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    redirect_uri,
                    response_type: 'id_token',
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.exist
            expect(error).to.equal('invalid_request')
            const error_description = responseURL.searchParams.get('error_description')
            expect(error_description).to.exist
            expect(error_description).to.equal('missing scope')
        })
    })
    describe('Missing openid scope', function() {
        it('should fail', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    redirect_uri,
                    response_type: 'id_token',
                    scope: 'email',
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.exist
            expect(error).to.equal('invalid_request')
            const error_description = responseURL.searchParams.get('error_description')
            expect(error_description).to.exist
            expect(error_description).to.equal('missing openid scope')
        })
    })
})
