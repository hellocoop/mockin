import { expect } from 'chai'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)


import {users} from '../src/users.js'
import { ISSUER } from '../src/config.js'

const client_id = 'client_id-value'
const nonce = 'nonce-value'
const redirect_uri = 'https://redirect_uri-value'

describe('Mock User Tests', function() {
    beforeEach(async function() {
        const response = await fastify.inject({
            method: 'DELETE',
            url: '/mock',
        })
        expect(response.statusCode).to.equal(200)
    })
    afterEach(async function() {
        const response = await fastify.inject({
            method: 'DELETE',
            url: '/mock',
        })
        expect(response.statusCode).to.equal(200)
    })
    describe('PUT /mock/user/1', function() {
        it('should return users[1]', async function() {
            // set MOCK.claims = users[1]
            const putResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/user/1',
            })
            expect(putResponse.statusCode).to.equal(200)
            // GET /authorize
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    redirect_uri,
                    response_type: 'id_token',
                    scope: 'openid email picture name',
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.not.exist
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.exist
            // POST /oauth/introspect
            const payload = new URLSearchParams({
                token: id_token,
                nonce,
                client_id,
            }).toString()
            const postResponse = await fastify.inject({
                method: 'POST',
                url: '/oauth/introspect',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                payload,
            })
            expect(postResponse.statusCode).to.equal(200)
            const postData = await postResponse.json()
            expect(postData).to.exist
            expect(postData.active).to.exist
            expect(postData.active).to.equal(true)
            expect(postData.email).to.exist
            expect(postData.email).to.equal(users[1].email)
            expect(postData.picture).to.exist
            expect(postData.picture).to.equal(users[1].picture)
            expect(postData.name).to.exist
            expect(postData.name).to.equal(users[1].name)
            expect(postData.sub).to.exist
            expect(postData.sub).to.equal(users[1].sub)
            expect(postData.iss).to.exist
            expect(postData.iss).to.equal(ISSUER)
            expect(postData.aud).to.exist
            expect(postData.aud).to.equal(client_id)
            expect(postData.nonce).to.exist
            expect(postData.nonce).to.equal(nonce)
            expect(postData.email_verified).to.exist
            expect(postData.email_verified).to.equal(true)
        })
    })
    describe('PUT /mock/claims', function() {
        it('should return email:"mock@mock.com"', async function() {
            // set MOCK.claims = users[1]
            const putResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/claims',
                payload: { email: 'mock@mock.com' },
                headers: { 'content-type': 'application/json' }
            })
            expect(putResponse.statusCode).to.equal(200)
            // GET /authorize
            const response = await fastify.inject({
                method: 'GET',
                url: '/authorize?' + new URLSearchParams({
                    client_id,
                    nonce,
                    redirect_uri,
                    response_type: 'id_token',
                    scope: 'openid email',
                })
            })
            expect(response.statusCode).to.equal(302)
            const location = response.headers?.location
            expect(location).to.contain('https://redirect_uri-value')
            const responseURL = new URL(location)
            const error = responseURL.searchParams.get('error')
            expect(error).to.not.exist
            const id_token = responseURL.searchParams.get('id_token')
            expect(id_token).to.exist
            // POST /oauth/introspect
            const payload = new URLSearchParams({
                token: id_token,
                nonce,
                client_id,
            }).toString()
            const postResponse = await fastify.inject({
                method: 'POST',
                url: '/oauth/introspect',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                payload,
            })
            expect(postResponse.statusCode).to.equal(200)
            const postData = await postResponse.json()
            expect(postData).to.exist
            expect(postData.active).to.exist
            expect(postData.active).to.equal(true)
            expect(postData.email).to.exist
            expect(postData.email).to.equal('mock@mock.com')
            expect(postData.sub).to.equal(users[0].sub)
            expect(postData.iss).to.exist
            expect(postData.iss).to.equal(ISSUER)
            expect(postData.aud).to.exist
            expect(postData.aud).to.equal(client_id)
            expect(postData.nonce).to.exist
            expect(postData.nonce).to.equal(nonce)
            expect(postData.email_verified).to.exist
            expect(postData.email_verified).to.equal(true)
        })
    })
})
