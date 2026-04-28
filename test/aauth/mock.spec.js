import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

describe('AAuth Mock Configuration', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('returns default config with auto_approve=true', async function () {
        const response = await fastify.inject({
            method: 'GET',
            url: '/mock/aauth',
        })
        expect(response.statusCode).to.equal(200)
        const data = response.json()
        expect(data.auto_approve).to.equal(true)
        expect(data.permission).to.equal('granted')
        expect(data.token_lifetime).to.equal(3600)
    })

    it('updates requirement to interaction', async function () {
        const response = await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ requirement: 'interaction' }),
        })
        expect(response.statusCode).to.equal(200)
        expect(response.json().requirement).to.equal('interaction')
    })

    it('sets error injection', async function () {
        const response = await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ error: 'denied' }),
        })
        expect(response.statusCode).to.equal(200)
        expect(response.json().error).to.equal('denied')
    })

    it('flips permission to denied with reason', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                permission: 'denied',
                permission_reason: 'unsafe action',
            }),
        })
        const response = await fastify.inject({
            method: 'GET',
            url: '/mock/aauth',
        })
        expect(response.json().permission).to.equal('denied')
        expect(response.json().permission_reason).to.equal('unsafe action')
    })

    it('DELETE /mock resets aauth config', async function () {
        await fastify.inject({
            method: 'PUT',
            url: '/mock/aauth',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                auto_approve: false,
                requirement: 'interaction',
                error: 'denied',
            }),
        })
        await fastify.inject({ method: 'DELETE', url: '/mock' })
        const data = (
            await fastify.inject({ method: 'GET', url: '/mock/aauth' })
        ).json()
        expect(data.auto_approve).to.equal(true)
        expect(data.requirement).to.be.null
        expect(data.error).to.be.null
    })
})
