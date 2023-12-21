// Mock API 

import authorize from './authorize.js'
import * as mock from './mock.js'
import * as oauth from './oauth.js'

const cors = async (req, res) => {
    res.header('Access-Control-Allow-Origin', '*')
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    res.header('Access-Control-Allow-Credentials', 'true')
    res.send(200)
}


export default function (fastify) {      
    fastify.get('/authorize', authorize)

    fastify.post('/oauth/token', oauth.token)
    fastify.post('/oauth/introspect', oauth.introspect)
    fastify.get('/oauth/userinfo', oauth.userinfo)
    fastify.post('/oauth/userinfo', oauth.userinfo)
    
    fastify.get('/.well-known/openid-configuration', oauth.wellknown)
    fastify.get('/jwks', oauth.jwks)
    //mock config
    fastify.get('/mock', mock.get)
    fastify.delete('/mock',mock.delete)
    fastify.put('/mock/user/:user',mock.put)
    fastify.put('/mock/oauth/:mock',mock.put)
    fastify.delete('/mock/oauth/:mock',mock.delete)
    fastify.put('/mock/:mock', mock.put)
    fastify.delete('/mock/:mock', mock.delete)
    // CORS
    fastify.options('/*', cors)
    return fastify    
}