import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

describe('AAuth Mock Configuration Tests', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    describe('GET /mock/aauth', function () {
        it('should return default config with auto_grant true', async function () {
            const response = await fastify.inject({
                method: 'GET',
                url: '/mock/aauth',
            })
            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.auto_grant).to.equal(true)
        })
    })

    describe('PUT /mock/aauth', function () {
        it('should update auto_grant to false', async function () {
            const response = await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ auto_grant: false }),
            })
            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.auto_grant).to.equal(false)
        })

        it('should set interaction_required', async function () {
            const response = await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ interaction_required: true }),
            })
            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.interaction_required).to.equal(true)
        })

        it('should set error', async function () {
            const response = await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ error: 'access_denied' }),
            })
            expect(response.statusCode).to.equal(200)
            const data = response.json()
            expect(data.error).to.equal('access_denied')
        })
    })

    describe('DELETE /mock resets AAuth config', function () {
        it('should reset AAuth config on DELETE /mock', async function () {
            // Set custom config
            await fastify.inject({
                method: 'PUT',
                url: '/mock/aauth',
                headers: { 'content-type': 'application/json' },
                payload: JSON.stringify({ auto_grant: false, error: 'access_denied' }),
            })
            // Reset all mock state
            await fastify.inject({ method: 'DELETE', url: '/mock' })
            // Verify reset
            const response = await fastify.inject({
                method: 'GET',
                url: '/mock/aauth',
            })
            const data = response.json()
            expect(data.auto_grant).to.equal(true)
            expect(data.error).to.be.undefined
        })
    })
})
