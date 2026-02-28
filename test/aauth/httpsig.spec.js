import { expect } from 'chai'
import Fastify from 'fastify'
import api from '../../src/api.js'

const fastify = Fastify()
api(fastify)

describe('AAuth HTTPSig Verification Tests', function () {
    beforeEach(async function () {
        await fastify.inject({ method: 'DELETE', url: '/mock' })
    })

    it('should return 401 for unsigned request', async function () {
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({ scope: 'openid' }),
        })
        expect(response.statusCode).to.equal(401)
        const data = response.json()
        expect(data.error).to.equal('invalid_signature')
    })

    it('should return 401 for malformed signature headers', async function () {
        const response = await fastify.inject({
            method: 'POST',
            url: '/aauth/token',
            headers: {
                'content-type': 'application/json',
                'signature': 'sig=:bogus:',
                'signature-input': 'sig=("@method");created=1234567890',
                'signature-key': 'sig=:hwk:bogus:',
            },
            payload: JSON.stringify({ scope: 'openid' }),
        })
        expect(response.statusCode).to.equal(401)
    })
})
