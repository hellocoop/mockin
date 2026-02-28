// aauth/mock.js — AAuth mock configuration management

import { clearPendingRequests } from './state.js'

let AAUTH_MOCK = {
    auto_grant: true,
}

export function getConfig() {
    return AAUTH_MOCK
}

export function setConfig(config) {
    AAUTH_MOCK = { ...AAUTH_MOCK, ...config }
}

export function resetConfig() {
    AAUTH_MOCK = { auto_grant: true }
    clearPendingRequests()
}

export const get = async (req, res) => {
    return res.send(AAUTH_MOCK)
}

export const put = async (req, res) => {
    const body = req.body || {}
    if (body.auto_grant !== undefined) AAUTH_MOCK.auto_grant = !!body.auto_grant
    if (body.interaction_required !== undefined) AAUTH_MOCK.interaction_required = !!body.interaction_required
    if (body.error !== undefined) AAUTH_MOCK.error = body.error || undefined
    if (body.claims !== undefined) AAUTH_MOCK.claims = body.claims || undefined
    if (body.token_lifetime !== undefined) AAUTH_MOCK.token_lifetime = body.token_lifetime || 3600
    return res.send(AAUTH_MOCK)
}
