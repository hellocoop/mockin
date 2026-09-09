// The connection ceremony — a resource that fronts an upstream the person
// must link.
//
// The resource mints a CONNECTION-ONLY resource token: no `scope`, no `r3_*`,
// and an `interaction_code` naming the pending record it is holding. The PS
// issues nothing. It puts the person in front of the resource's own published
// `interaction_endpoint` with that code and a callback, and the record
// terminates when the resource bounces the browser back —
// `connection_established`, no auth token.

import { expect } from 'chai'
import Fastify from 'fastify'

import api from '../../src/api.js'
import { ISSUER } from '../../src/config.js'
import {
    installMocks,
    postAuthToken,
    getPersonToken,
    mintResourceToken,
    signedRequest,
    RESOURCE_SERVER_URL,
} from './helpers.js'

const fastify = Fastify()
api(fastify)

const INTERACTION_CODE = 'ABCD-1234'

// A connection-only exchange, up to the PS's 202.
async function startConnection(overrides = {}) {
    const { person_token, agentToken } = await getPersonToken(fastify)
    const resourceToken = await mintResourceToken({
        presentedToken: person_token,
        scope: null,
        interaction_code: INTERACTION_CODE,
        ...overrides,
    })
    const response = await postAuthToken(fastify, {
        body: { resource_token: resourceToken, presented_token: person_token },
        agentToken,
    })
    return { response, agentToken, person_token }
}

// The pending code off the 202's AAuth-Requirement header.
const codeOf = (response) =>
    /code="([^"]+)"/.exec(response.headers['aauth-requirement'])?.[1]

describe('AAuth auth_token_endpoint — the connection ceremony', function () {
    beforeEach(async function () {
        await installMocks(fastify)
    })

    it('answers 202 requirement=interaction with a code and no url', async function () {
        const { response } = await startConnection()
        expect(response.statusCode).to.equal(202)
        const requirement = response.headers['aauth-requirement']
        expect(requirement).to.match(/^requirement=interaction/)
        // The URL is composed by the recipient from the resource's published
        // interaction_endpoint; the header carries the code alone.
        expect(requirement).to.not.include('url=')
        expect(codeOf(response)).to.be.a('string')
        expect(response.headers.location).to.include('/aauth/pending/')
        expect(response.json().auth_token).to.be.undefined
    })

    it('sends the person to the resource interaction_endpoint with the code and a callback', async function () {
        const { response } = await startConnection()
        const consent = await fastify.inject({
            method: 'GET',
            url: `/aauth/consent?code=${codeOf(response)}`,
        })
        expect(consent.statusCode).to.equal(302)
        const target = new URL(consent.headers.location)
        expect(target.origin + target.pathname).to.equal(
            `${RESOURCE_SERVER_URL}/oauth/start`,
        )
        // The code the RESOURCE is holding, not the PS's pending code.
        expect(target.searchParams.get('code')).to.equal(INTERACTION_CODE)
        expect(target.searchParams.get('callback')).to.include(`${ISSUER}/aauth/bounce/`)
    })

    it('terminates on the bounce, not on the person arriving at consent', async function () {
        const { response, agentToken } = await startConnection()
        const path = new URL(response.headers.location).pathname
        const poll = async () => {
            const { headers } = await signedRequest({ method: 'GET', path, agentToken })
            return fastify.inject({ method: 'GET', url: path, headers })
        }

        // The person has been sent to the resource but it has not finished.
        await fastify.inject({ method: 'GET', url: `/aauth/consent?code=${codeOf(response)}` })
        expect((await poll()).statusCode).to.equal(202)

        // The resource returns the browser.
        const bounce = await fastify.inject({
            method: 'GET',
            url: `/aauth/bounce/${codeOf(response)}`,
        })
        expect(bounce.statusCode).to.equal(200)

        const done = await poll()
        expect(done.statusCode).to.equal(200)
        expect(done.json()).to.deep.equal({ status: 'connection_established' })
        expect(done.json().auth_token).to.be.undefined
    })

    it('a bounce carrying an error fails the record', async function () {
        const { response, agentToken } = await startConnection()
        await fastify.inject({ method: 'GET', url: `/aauth/consent?code=${codeOf(response)}` })
        await fastify.inject({
            method: 'GET',
            url: `/aauth/bounce/${codeOf(response)}?error=access_denied`,
        })
        const path = new URL(response.headers.location).pathname
        const { headers } = await signedRequest({ method: 'GET', path, agentToken })
        const poll = await fastify.inject({ method: 'GET', url: path, headers })
        expect(poll.statusCode).to.equal(403)
        expect(poll.json().error).to.equal('access_denied')
    })

    it('rejects a scope-less token that carries no interaction_code', async function () {
        const { response } = await startConnection({ interaction_code: null })
        expect(response.statusCode).to.equal(400)
        expect(response.json().error).to.equal('invalid_resource_token')
        expect(response.json().detail).to.include('interaction_code')
    })

    it('rejects r3 without scope', async function () {
        const { response } = await startConnection({
            r3_uri: 'https://rs.example/r3/abc',
            r3_s256: 'x'.repeat(43),
        })
        expect(response.statusCode).to.equal(400)
        expect(response.json().detail).to.include('r3_uri without scope')
    })

    it('an empty scope is a scoped token, not a connection', async function () {
        // An existing R3 test mints `scope: ''`. Absent and empty differ.
        const { response } = await startConnection({ scope: '', interaction_code: null })
        expect(response.statusCode).to.equal(200)
        expect(response.json().auth_token).to.be.a('string')
    })

    it('403 user_unreachable when the agent cannot drive an interaction', async function () {
        const { person_token, agentToken } = await getPersonToken(fastify)
        const resourceToken = await mintResourceToken({
            presentedToken: person_token,
            scope: null,
            interaction_code: INTERACTION_CODE,
        })
        const response = await postAuthToken(fastify, {
            body: {
                resource_token: resourceToken,
                presented_token: person_token,
                capabilities: ['payment'],
            },
            agentToken,
        })
        expect(response.statusCode).to.equal(403)
        expect(response.json().error).to.equal('user_unreachable')
    })
})
