import { expect } from 'chai'
import { readFile } from 'fs/promises'
import Fastify from 'fastify'

import api from '../src/api.js'
const fastify = Fastify()
api(fastify)

const pkgVersion = JSON.parse(await readFile('package.json', 'utf8')).version

describe('Version Endpoint Tests', function() {
    describe('GET /version', function() {
        it('should return version matching package.json', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/version',
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data).to.exist
            expect(data.version).to.equal(pkgVersion)
        })
    })

    describe('GET /', function() {
        it('should return same version response', async function() {
            const response = await fastify.inject({
                method: 'GET',
                url: '/',
            })
            expect(response.statusCode).to.equal(200)
            const data = await response.json()
            expect(data).to.exist
            expect(data.version).to.equal(pkgVersion)
        })
    })
})
