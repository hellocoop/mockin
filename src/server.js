// server.js

import fastify from 'fastify'
import api from './api.js';

import { PORT, IP } from './config.js'

// mock server

const fastify = fastify({
    disableRequestLogging: true,
    logger: {
      level: 'error',
      timestamp: false,
      base: undefined,
    }
  })

api(fastify)   

fastify.listen({port: PORT, host: IP})
    .then((address) => fastify.log.warn(`Mock server listening on ${address}`))
    .catch((err) => {
        fastify.log.error(err)
        process.exit(1)
    })