import { expect } from 'chai'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

describe('Mock Management Tests', function() {
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
    describe('PUT /mock/authorize', function() {
        it('should return MOCK.authorize.error', async function() {
            const response = await fastify.inject({
                method: 'PUT',
                url: '/mock/authorize',
                payload: { error: 'access_denied' },
                headers: { 'content-type': 'application/json' }
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data).to.exist
            expect(data.MOCK).to.exist
            expect(data.MOCK).to.deep.equal({
                authorize: { error: 'access_denied' }
            })
        })
    })
    describe('GET /mock', function() {
        it('should return MOCK.authorize.error', async function() {
            const putResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/authorize',
                payload: { error: 'access_denied' },
                headers: { 'content-type': 'application/json' }
            })
            expect(putResponse.statusCode).to.equal(200)
            const response = await fastify.inject({
                method: 'GET',
                url: '/mock',
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data).to.exist
            expect(data.MOCK).to.exist
            expect(data.MOCK).to.deep.equal({
                authorize: { error: 'access_denied' }
            })
        })
    })
    describe('DELETE /mock', function() {
        it('should return empty MOCK object', async function() {
            const putResponse = await fastify.inject({
                method: 'PUT',
                url: '/mock/authorize',
                payload: { error: 'access_denied' },
                headers: { 'content-type': 'application/json' }
            })
            expect(putResponse.statusCode).to.equal(200)
            const getResponse = await fastify.inject({
                method: 'GET',
                url: '/mock',
            })
            expect(getResponse.statusCode).to.equal(200)
            const getData = await getResponse.json()
            expect(getData).to.exist
            expect(getData.MOCK).to.exist
            expect(getData.MOCK).to.deep.equal({
                authorize: { error: 'access_denied' }
            })
            const response = await fastify.inject({
                method: 'DELETE',
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
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data).to.exist
            expect(data.MOCK).to.exist
            expect(data.MOCK).to.deep.equal({})
        })
    })

})
