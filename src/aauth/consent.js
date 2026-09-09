// aauth/consent.js — GET /aauth/consent?code=…&callback=…
//                     GET /aauth/bounce/:code
//
// User-facing consent endpoint. The agent directs the user's browser here
// after receiving requirement=interaction; mockin auto-approves the
// pending entry and (if a callback is supplied) redirects the browser
// back to the agent so it can resume polling.
//
// This endpoint is unauthenticated by design — it is a normal browser
// navigation, not a signed agent call. The single-use `code` is the
// authorization handle.

import { ISSUER } from '../config.js'
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

    // A connection is not the PS's to approve. The person has to link an
    // account at the resource, so send them to the resource's own
    // interaction_endpoint with the code the resource is holding, and a
    // callback to bounce back to. The record terminates on that bounce —
    // the resource finishing is the event, not the person arriving here.
    if (entry.kind === 'connection') {
        if (entry.status === 'approved') {
            reply.header('Content-Type', 'text/html')
            return reply.send(
                '<!doctype html><html><body><h1>Connected</h1>' +
                    '<p>You may close this window.</p></body></html>',
            )
        }
        const target = new URL(entry.interaction_endpoint)
        target.searchParams.set('code', entry.interaction_code)
        target.searchParams.set('callback', `${ISSUER}/aauth/bounce/${entry.code}`)
        // A callback supplied here is where the AGENT wants the person to end
        // up; remember it so the bounce can forward once the resource is done.
        if (callback) {
            try {
                updatePending(entry.id, { agent_callback: new URL(callback).toString() })
            } catch {
                return problem(reply, 400, 'invalid_request', 'invalid callback url')
            }
        }
        return reply.redirect(target.toString())
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

// GET /aauth/bounce/:code
//
// Where the resource sends the person's browser once its own ceremony is
// finished — the `callback` the consent redirect above handed it. This, not a
// visit to /aauth/consent, is what terminates a connection record: the resource
// completing is the event that says the account is linked.
//
// Unauthenticated by design, like /aauth/consent: a browser navigation whose
// single-use code is the handle. An `error` query parameter is the resource
// reporting that the person abandoned or the upstream refused.
export const bounce = async (req, reply) => {
    const { code } = req.params || {}
    const { error } = req.query || {}

    const entry = getPendingByCode(code)
    if (!entry) {
        return problem(reply, 400, 'invalid_request', 'unknown code')
    }
    if (entry.kind !== 'connection') {
        return problem(
            reply, 400, 'invalid_request',
            `pending ${entry.id} is a ${entry.kind} record, not a connection`,
        )
    }

    if (error) {
        updatePending(entry.id, { status: 'error', error: String(error) })
    } else {
        updatePending(entry.id, {
            status: 'approved',
            connection_established: true,
        })
    }

    if (entry.agent_callback) return reply.redirect(entry.agent_callback)

    reply.header('Content-Type', 'text/html')
    return reply.send(
        '<!doctype html><html><body>' +
            (error
                ? `<h1>Not connected</h1><p>${String(error)}</p>`
                : '<h1>Connected</h1><p>You may close this window.</p>') +
            '</body></html>',
    )
}
