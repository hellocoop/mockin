// aauth/interaction.js — /aauth/interaction handler (GET, auto-approves)

import { getConfig } from './mock.js'
import defaultUser from '../users.js'
import { getPendingByCode, updatePendingRequest } from './state.js'

export const interaction = async (req, res) => {
    const config = getConfig()
    const { code, callback } = req.query

    if (!code) {
        return res.code(400).send({
            error: 'invalid_request',
            error_description: 'Missing code',
        })
    }

    const pending = getPendingByCode(code)
    if (!pending) {
        return res.code(400).send({
            error: 'invalid_request',
            error_description: 'Unknown code',
        })
    }

    const errorValues = ['denied', 'abandoned', 'expired', 'invalid_code', 'access_denied']
    if (config.error && errorValues.includes(config.error)) {
        const error = config.error === 'access_denied' ? 'denied' : config.error
        updatePendingRequest(pending.id, { status: 'error', error })
        if (callback) {
            const url = new URL(callback)
            url.searchParams.set('error', error)
            return res.redirect(url.toString())
        }
        const statusCode = error === 'expired' ? 408 : error === 'invalid_code' ? 410 : 403
        return res.code(statusCode).send({ error })
    }

    // Mock auto-approval
    updatePendingRequest(pending.id, {
        status: 'approved',
        user_sub: defaultUser.sub,
    })

    if (callback) {
        return res.redirect(callback)
    }

    res.header('Content-Type', 'text/html')
    return res.send('<html><body><h1>Authorization Approved</h1><p>You may close this window.</p></body></html>')
}
