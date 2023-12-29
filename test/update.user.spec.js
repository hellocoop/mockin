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

const injectAuthToken = {
    method: 'GET',
    url: '/authorize?' + new URLSearchParams({
        client_id,
        nonce,
        redirect_uri,
        response_type: 'id_token',
        scope: 'openid name email',
    })
}


describe('Update User Test', function() {
    beforeEach(async function() {
        const mockResponse = await fastify.inject({
            method: 'DELETE',
            url: '/mock',
        })
        expect(mockResponse.statusCode).to.equal(200)
    })

    describe('openid profle_update email', function() {
        it('should return updated profile', async function() {
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
            const { iss, aud, sub, nonce: _nonce, active, name, email, email_verified } = data
            expect(iss).to.equal(ISSUER)
            expect(aud).to.equal(client_id)
            expect(sub).to.equal(defaultUser.sub)
            expect(_nonce).to.equal(nonce)
            expect(active).to.equal(true)
            expect(name).to.equal(defaultUser.name)
            expect(email).to.equal(defaultUser.email)
            expect(email_verified).to.equal(true)
            // set up mock data
            const mockResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/claims',
                payload: { email: 'mock@mock.com' },
                headers: { 'content-type': 'application/json' }
            })
            expect(mockResponse.statusCode).to.equal(200)
            const mockData = await mockResponse.json()
            expect(mockData).to.exist
            expect(mockData.MOCK).to.exist
            expect(mockData.MOCK.claims).to.exist
            expect(mockData.MOCK.claims.email).to.exist
            expect(mockData.MOCK.claims.email).to.equal('mock@mock.com')
            const updateResponse = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    redirect_uri,
                    response_type: 'id_token',
                    scope: 'openid profile_update email',
                })
            })
            expect(updateResponse.statusCode).to.equal(302)
            const updateLocation = updateResponse.headers?.location
            const updateResponseURL = new URL(updateLocation)
            const updateErro = updateResponseURL.searchParams.get('error')
            expect(updateErro).to.not.exist
            const updateToken = updateResponseURL.searchParams.get('id_token')
            expect(updateToken).to.exist
            const updateIntrospection = await fastify.inject({
                url: '/oauth/introspect',
                method: 'POST', 
                payload: new URLSearchParams({ token: updateToken, client_id, nonce }).toString(),
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
            })
            expect(updateIntrospection.statusCode).to.equal(200)
            const updateData = await updateIntrospection.json()
            const { iss: updateIss, aud: updateAud, sub: updateSub, nonce: updateNonce, active: updateActive, name: updateName, email: updateEmail, email_verified: updateEmailVerified } = updateData
            expect(updateIss).to.equal(ISSUER)
            expect(updateAud).to.equal(client_id)
            expect(updateSub).to.equal(defaultUser.sub)
            expect(updateNonce).to.equal(nonce)
            expect(updateActive).to.equal(true)
            expect(updateName).to.equal(defaultUser.name)
            expect(updateEmail).to.equal('mock@mock.com')
            expect(updateEmailVerified).to.equal(true)
         })
    })

})
