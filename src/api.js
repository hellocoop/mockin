// Mock API
import { Readable } from 'stream'
import fastifyFormbody from '@fastify/formbody'
import cors from '@fastify/cors'

import authorize from './authorize.js'
import version from './version.js'
import * as mock from './mock.js'
import * as oauth from './oauth.js'
import * as command from './command.js'
import * as aauth from './aauth/index.js'
import * as invite from './invite.js'

// Buffer the raw request body so HTTPSig verification can recompute the
// content digest. Fastify reads streams once; we read it into rawBody and
// re-feed a Readable so JSON parsing still works downstream.
const captureRawBody = async (request, reply, payload) => {
    const chunks = []
    for await (const chunk of payload) chunks.push(chunk)
    const buf = Buffer.concat(chunks)
    request.rawBody = buf
    return Readable.from(buf)
}

export default function (fastify) {
    fastify.register(fastifyFormbody)
    fastify.register(cors, {
        exposedHeaders: [
            'AAuth-Requirement', 'Accept-Signature', 'Signature-Error', 'Location',
        ],
    })
    // mock APIs
    fastify.get('/authorize', authorize)
    fastify.post('/oauth/token', oauth.token)
    fastify.post('/oauth/introspect', oauth.introspect)
    fastify.get('/oauth/userinfo', oauth.userinfo)
    fastify.post('/oauth/userinfo', oauth.userinfo)
    fastify.get('/.well-known/openid-configuration', oauth.wellknown)
    fastify.get('/jwks', oauth.jwks)

    // AAuth: discovery
    fastify.get('/.well-known/aauth-person.json', aauth.metadata)
    fastify.get('/aauth/jwks.json', aauth.jwks)

    // AAuth: token endpoint
    fastify.post('/aauth/token', {
        preParsing: captureRawBody,
        preHandler: aauth.verifyPreHandler,
    }, aauth.token)

    // AAuth: pending endpoint (poll, clarify, cancel) — verification runs
    // inside the handler since bootstrap polls use hwk and others use jwt.
    fastify.get('/aauth/pending/:id', aauth.pendingGet)
    fastify.post('/aauth/pending/:id', {
        preParsing: captureRawBody,
    }, aauth.pendingPost)
    fastify.delete('/aauth/pending/:id', aauth.pendingDelete)

    // AAuth: governance endpoints
    fastify.post('/aauth/permission', {
        preParsing: captureRawBody,
        preHandler: aauth.verifyPreHandler,
    }, aauth.permission)
    fastify.post('/aauth/audit', {
        preParsing: captureRawBody,
        preHandler: aauth.verifyPreHandler,
    }, aauth.audit)
    fastify.post('/aauth/interaction', {
        preParsing: captureRawBody,
        preHandler: aauth.verifyPreHandler,
    }, aauth.interaction)

    // AAuth: bootstrap (uses hwk scheme, has its own verify path)
    fastify.post('/aauth/bootstrap', {
        preParsing: captureRawBody,
    }, aauth.bootstrap)

    // AAuth: user-facing consent (browser navigation, no signing)
    fastify.get('/aauth/consent', aauth.consent)

    // Invite endpoints (mirrors wallet's external contract)
    fastify.get('/invite', invite.entry)
    fastify.post('/invite', invite.create)
    fastify.put('/invite/:id', invite.resend)
    fastify.delete('/invite/:id', invite.retract)
    fastify.get('/user/invite', invite.userInvites)
    fastify.get('/invitation/:id', invite.invitation)
    fastify.put('/invitation/:id', invite.accept)
    fastify.delete('/invitation/:id', invite.decline)
    fastify.post('/invitation/:id/report', invite.report)
    // Invite mock controls
    fastify.get('/mock/invite', invite.mockGet)
    fastify.put('/mock/invite', invite.mockPut)

    // config mock
    fastify.get('/mock', mock.get)
    fastify.get('/mock/users', mock.users)
    fastify.put('/mock/user/:user', mock.user)
    fastify.put('/mock/oauth/:mock', mock.put)
    fastify.put('/mock/:mock', mock.put)
    // AAuth mock management
    fastify.get('/mock/aauth', aauth.mockGet)
    fastify.put('/mock/aauth', aauth.mockPut)
    // reset mock
    fastify.delete('/mock', mock.delete)
    // version
    fastify.get('/version', version)
    fastify.get('/', version)
    // metadata command token
    fastify.get('/command/mock', command.mock)
    return fastify
}
