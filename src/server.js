// server.js

import fastify from 'fastify'

import api from './api.js';

import { PORT, IP } from './config.js'

// mock server

const mockin = fastify({
    disableRequestLogging: true,
    logger: {
      level: 'error',
      timestamp: false,
      base: undefined,
    }
  })
  

api(mockin)   

mockin.listen({port: PORT, host: IP})
    .then((address) => console.log(`Mock server listening on ${address}`))
    .catch((err) => {
      mockin.log.error(err)
        process.exit(1)
    })