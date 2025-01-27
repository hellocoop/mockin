// Mock API 
import fastifyFormbody from '@fastify/formbody'
import cors from '@fastify/cors'

import authorize from './authorize.js'
import version from './version.js'
import * as mock from './mock.js'
import * as oauth from './oauth.js'
import * as command from './command.js'

export default function (fastify) {      
    fastify.register(fastifyFormbody)
    fastify.register(cors)
    // mock APIs
    fastify.get('/authorize', authorize)
    fastify.post('/oauth/token', oauth.token)
    fastify.post('/oauth/introspect', oauth.introspect)
    fastify.get('/oauth/userinfo', oauth.userinfo)
    fastify.post('/oauth/userinfo', oauth.userinfo)
    fastify.get('/.well-known/openid-configuration', oauth.wellknown)
    fastify.get('/jwks', oauth.jwks)
    // config mock
    fastify.get('/mock', mock.get)
    fastify.get('/mock/users', mock.users)
    fastify.put('/mock/user/:user', mock.user)
    fastify.put('/mock/oauth/:mock', mock.put)
    fastify.put('/mock/:mock', mock.put)
    // reset mock
    fastify.delete('/mock', mock.delete)
    // version
    fastify.get('/version', version)
    fastify.get('/', version)
    // metadata command token
    fastify.get('/command/mock', command.mock)
    return fastify    
}