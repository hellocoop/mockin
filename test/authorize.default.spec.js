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

const injectAuthToken = {
    method: 'GET',
    url: '/authorize?' + new URLSearchParams({
        client_id,
        nonce,
        redirect_uri,
        response_type: 'id_token',
        scope: 'openid',
    })
}

describe('Default Authorization Tests', function() {
    describe('Authorize Endpoint', function() {
        it('should get token', async function() {
            const response = await fastify.inject(injectAuthToken)
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.exist
        })
    })
    describe('Introspection Endpoint', function() {
        it('should parse token', async function() {
            const authResponse = await fastify.inject(injectAuthToken)
            const location = authResponse.headers?.location
            const responseURL = new URL(location)
            const token = responseURL.searchParams.get('id_token')
            const response = await fastify.inject({
                url: '/oauth/introspect',
                method: 'POST', 
                payload: new URLSearchParams({ token, client_id, nonce }).toString(),
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            const { iss, aud, sub, nonce: _nonce, active } = data
            expect(iss).to.equal(ISSUER)
            expect(aud).to.equal(client_id)
            expect(sub).to.equal(defaultUser.sub)
            expect(_nonce).to.equal(nonce)
            expect(active).to.equal(true)
         })
    })
    describe('.well-known/openid-configuration Endpoint', function() {
        it('should return openid-configuration', async function() {
            const response = await fastify.inject({
                url: '/.well-known/openid-configuration',
                method: 'GET',
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            const { issuer, authorization_endpoint, token_endpoint, introspection_endpoint, userinfo_endpoint, jwks_uri } = data
            expect(issuer).to.equal(ISSUER)
            expect(authorization_endpoint).to.equal(`${ISSUER}/authorize`)
            expect(token_endpoint).to.equal(`${ISSUER}/oauth/token`)
            expect(introspection_endpoint).to.equal(`${ISSUER}/oauth/introspect`)
            expect(userinfo_endpoint).to.equal(`${ISSUER}/oauth/userinfo`)
            expect(jwks_uri).to.equal(`${ISSUER}/jwks`)
         })
    })
    describe('Verify ID Token', function() {
        it('should return jwks', async function() {
            const response = await fastify.inject({
                url: '/jwks',
                method: 'GET',
            })
            expect(response.statusCode).to.equal(200)
            const jwks = await response.json()
            const pems = {}
            jwks.keys.forEach( jwk => {
                pems[jwk.kid] = jwkToPem(jwk)
            })
            const authResponse = await fastify.inject(injectAuthToken)
            const location = authResponse.headers?.location
            const responseURL = new URL(location)
            const id_token = responseURL.searchParams.get('id_token')
            const { header, payload } = jwt.decode(id_token, { complete: true })
            expect(header).to.exist
            expect(payload).to.exist
            expect(header?.alg).to.equal('RS256')
            expect(header?.typ).to.equal('JWT')
            expect(header?.kid).to.exist
            const key = pems[header?.kid]
            expect(key).to.exist
            const options = {
                algorithms: ['RS256'],
                issuer: ISSUER,
                audience: client_id,
                nonce
            }
            try {
                const decoded = jwt.verify(id_token, key, options)
                expect(decoded).to.exist
            } catch (err) {
                console.error(err)
                expect(err).to.not.exist
            }
         })
    })
    const injectAuthCode = {
        method: 'GET',
        url: '/authorize?' + new URLSearchParams({
            client_id,
            nonce,
            redirect_uri,
            scope: 'openid',
            response_type: 'code',
            code_challenge_method: 'S256',
            code_challenge,
        })
    }
    describe('Authorize Endpoint', function() {
        it('should get code using PKCE', async function() {
            const response = await fastify.inject(injectAuthCode)
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const code = responseURL.searchParams.get('code')
            expect(code).to.exist
        })
    })
    let access_token = null
    describe('Token Endpoint', function() {
        it('should return an id_token and access_token', async function() {
            const authResponse = await fastify.inject(injectAuthCode)
            const location = authResponse.headers?.location
            const responseURL = new URL(location)
            const code = responseURL.searchParams.get('code')
            const payload = new URLSearchParams({
                code, 
                client_id, 
                redirect_uri, 
                grant_type: 'authorization_code',
                code_verifier 
            }).toString()
            const response = await fastify.inject({
                url: '/oauth/token',
                method: 'POST', 
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                payload,
            })
            // expect(response.statusCode).to.equal(200)
            const data = await response.json()
            const { id_token, access_token } = data
            expect(id_token).to.exist
            expect(access_token).to.exist
            const { iss, aud, sub, nonce: _nonce } = jwt.decode(id_token)
            expect(iss).to.exist
            expect(aud).to.exist
            expect(sub).to.exist
            expect(_nonce).to.exist
            expect(iss).to.equal(ISSUER)
            expect(aud).to.equal(client_id)
            expect(sub).to.equal(defaultUser.sub)
            expect(_nonce).to.equal(nonce)
         })
    })
    describe('UserInfo Endpoint', function() {
        it('should return user info', async function() {
            const authResponse = await fastify.inject(injectAuthCode)
            const location = authResponse.headers?.location
            const responseURL = new URL(location)
            const code = responseURL.searchParams.get('code')
            const payload = new URLSearchParams({
                code, 
                client_id, 
                redirect_uri, 
                grant_type: 'authorization_code',
                code_verifier 
            }).toString()
            const tokenRespoonse = await fastify.inject({
                url: '/oauth/token',
                method: 'POST', 
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                payload,
            })
            const tokenData = await tokenRespoonse.json()
            const { access_token } = tokenData
            const response = await fastify.inject({
                url: '/oauth/userinfo',
                method: 'GET', 
                headers: { authorization: `Bearer ${access_token}` }
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            const { sub, iss } = data
            expect(iss).to.exist
            expect(sub).to.exist
            expect(sub).to.equal(defaultUser.sub)
            expect(iss).to.equal(ISSUER)
        })
    })
})
