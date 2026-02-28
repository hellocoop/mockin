// aauth/verify-sig.js — HTTPSig verification preHandler for Fastify

import { verify } from '@hellocoop/httpsig'

export const verifySig = async (request, reply) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`)

    const verifyRequest = {
        method: request.method,
        authority: url.host,
        path: url.pathname,
        query: url.search ? url.search.slice(1) : undefined,
        headers: request.headers,
        body: request.rawBody,
    }

    const result = await verify(verifyRequest, { strictAAuth: false })

    if (!result.verified) {
        reply.code(401).send({
            error: 'invalid_signature',
            error_description: result.error || 'HTTP signature verification failed',
        })
        return
    }

    request.aauth = result
}
