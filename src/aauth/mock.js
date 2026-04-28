// aauth/mock.js — AAuth mock configuration management
//
// Mockin acts as a Person Server (PS). The mock config controls how it
// responds to requests:
//   - auto-approve (default) → /aauth/token returns 200 + auth_token
//     immediately, no pending step
//   - deferred → returns 202 + pending; resolves on next /pending poll
//   - error injection per endpoint
//   - claim/grant overrides on issued auth_tokens
//   - trusted_servers preload for tests (skip JWKS network fetches)

import { clearPendingRequests } from './state.js'
import { resetEntityCache } from './entity-cache.js'

const DEFAULTS = () => ({
    // Token endpoint behaviour
    auto_approve: true,         // 200 + auth_token directly
    requirement: null,          // null | 'interaction' | 'approval' | 'clarification'
    clarification: null,        // markdown question to return
    // Error injection
    error: null,                // applies to /aauth/token unless scoped
    error_endpoint: null,       // restrict error to a specific endpoint
    // Token shape overrides
    token_lifetime: 3600,
    claims: null,               // identity claims to merge into auth_token
    r3_grants: null,            // { granted, conditional } override
    // Auxiliary endpoints
    permission: 'granted',      // 'granted' | 'denied'
    permission_reason: null,
    // Test-time JWKS / metadata preload
    //   trusted_servers: { '<server_url>': { metadata: {...}, jwks: {...} } }
    trusted_servers: {},
})

let CONFIG = DEFAULTS()

export function getConfig() {
    return CONFIG
}

export function setConfig(patch) {
    CONFIG = { ...CONFIG, ...patch }
}

export function resetConfig() {
    CONFIG = DEFAULTS()
    clearPendingRequests()
    resetEntityCache()
}

export const get = async (req, res) => {
    return res.send(CONFIG)
}

export const put = async (req, res) => {
    const body = req.body || {}
    const next = { ...CONFIG }
    const passthrough = [
        'auto_approve', 'requirement', 'clarification',
        'error', 'error_endpoint',
        'token_lifetime', 'claims', 'r3_grants',
        'permission', 'permission_reason',
    ]
    for (const k of passthrough) {
        if (body[k] !== undefined) next[k] = body[k]
    }
    if (body.trusted_servers !== undefined) {
        // Replace the registry wholesale; tests routinely overwrite it.
        next.trusted_servers = body.trusted_servers || {}
    }
    CONFIG = next
    return res.send(CONFIG)
}

// Helper used by handlers: check if mock-injected error applies here.
export function mockErrorFor(endpoint) {
    if (!CONFIG.error) return null
    if (CONFIG.error_endpoint && CONFIG.error_endpoint !== endpoint) return null
    return CONFIG.error
}
