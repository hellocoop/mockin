// Mock API 
import fastifyFormbody from '@fastify/formbody'
import cors from '@fastify/cors'

import authorize from './authorize.js'
import * as mock from './mock.js'
import * as oauth from './oauth.js'

export default function (fastify) {      
    fastify.register(fastifyFormbody)
    fastify.register(cors)

    fastify.get('/authorize', authorize)

    fastify.post('/oauth/token', oauth.token)
    fastify.post('/oauth/introspect', oauth.introspect)
    fastify.get('/oauth/userinfo', oauth.userinfo)
    fastify.post('/oauth/userinfo', oauth.userinfo)
    
    fastify.get('/.well-known/openid-configuration', oauth.wellknown)
    fastify.get('/jwks', oauth.jwks)
    //mock config
    fastify.delete('/mock', mock.delete)
    fastify.get('/mock', mock.get)
    fastify.get('/mock/users', mock.users)
    fastify.put('/mock/user/:user', mock.user)
    fastify.put('/mock/oauth/:mock', mock.put)
    fastify.delete('/mock/oauth/:mock', mock.delete)
    fastify.put('/mock/:mock', mock.put)
    fastify.delete('/mock/:mock', mock.delete)
    return fastify    
}