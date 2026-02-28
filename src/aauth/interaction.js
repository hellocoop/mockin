// aauth/interaction.js — /aauth/interaction handler (GET, auto-approves)

import { getConfig } from './mock.js'
import defaultUser from '../users.js'
import { getPendingByInteractionTicket, updatePendingRequest } from './state.js'

export const interaction = async (req, res) => {
    const config = getConfig()
    const { interaction_ticket } = req.query

    if (!interaction_ticket) {
        return res.code(400).send({
            error: 'invalid_request',
            error_description: 'Missing interaction_ticket',
        })
    }

    const pending = getPendingByInteractionTicket(interaction_ticket)
    if (!pending) {
        return res.code(400).send({
            error: 'invalid_request',
            error_description: 'Unknown interaction_ticket',
        })
    }

    if (config.error === 'access_denied') {
        updatePendingRequest(pending.requestTicket, { status: 'denied' })
        if (pending.callback_url) {
            const url = new URL(pending.callback_url)
            url.searchParams.set('error', 'access_denied')
            if (pending.callback_ticket) url.searchParams.set('callback_ticket', pending.callback_ticket)
            return res.redirect(url.toString())
        }
        return res.code(403).send({ error: 'access_denied' })
    }

    // Mock auto-approval
    updatePendingRequest(pending.requestTicket, {
        status: 'approved',
        user_sub: defaultUser.sub,
    })

    if (pending.callback_url) {
        const url = new URL(pending.callback_url)
        if (pending.callback_ticket) url.searchParams.set('callback_ticket', pending.callback_ticket)
        return res.redirect(url.toString())
    }

    res.header('Content-Type', 'text/html')
    return res.send('<html><body><h1>Authorization Approved</h1><p>You may close this window.</p></body></html>')
}
