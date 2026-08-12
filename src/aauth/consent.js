// aauth/consent.js — GET /aauth/consent?code=…&callback=…
//
// User-facing consent endpoint. The agent directs the user's browser here
// after receiving requirement=interaction; mockin auto-approves the
// pending entry and (if a callback is supplied) redirects the browser
// back to the agent so it can resume polling.
//
// This endpoint is unauthenticated by design — it is a normal browser
// navigation, not a signed agent call. The single-use `code` is the
// authorization handle.

import { getPendingByCode, updatePending } from './state.js'
import { problem } from './problem.js'

export const consent = async (req, reply) => {
    const { code, callback } = req.query || {}

    if (!code) {
        return problem(reply, 400, 'invalid_request', 'missing code')
    }

    const entry = getPendingByCode(code)
    if (!entry) {
        return problem(reply, 400, 'invalid_request', 'unknown code')
    }

    updatePending(entry.id, { status: 'approved' })

    if (callback) {
        let safe
        try {
            safe = new URL(callback).toString()
        } catch {
            return problem(reply, 400, 'invalid_request', 'invalid callback url')
        }
        return reply.redirect(safe)
    }

    reply.header('Content-Type', 'text/html')
    return reply.send(
        '<!doctype html><html><body>' +
            '<h1>Authorization approved</h1>' +
            '<p>You may close this window.</p>' +
            '</body></html>',
    )
}
