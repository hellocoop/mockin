// Mock API 

import { ISSUER } from './config.js'
import { randomUUID } from 'crypto'
import authorize from './authorize.js'
import mock from './mock.js'
import { token, introspect, userinfo, wellknown, jwks } from './oauth.js'

const cors = async (req, res) => {
    res.header('Access-Control-Allow-Origin', '*')
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    res.header('Access-Control-Allow-Credentials', 'true')
    res.send(200)
}

const noCache = async (req, res) => {
    res.header('Cache-Control', 'no-store')
    res.header('Pragma', 'no-cache')
}


export default function (fastify) {      
    fastify.get('/authorize', authorize)
    fastify.get('/mock', mock)
    fastify.post('/mock/:mock', mock)
// complete 
    fastify,options('/*', cors)
    fastify.post('/oauth/token', token)
    fastify.post('/oauth/introspect', introspect)
    fastify.post('/oauth/userinfo', userinfo)
    fastify.get('/oauth/userinfo', noCache, userinfo)
    fastify.get('/.well-known/openid-configuration', wellknown)
    fastify.get('/jwks', jwks)
    return fastify    
}