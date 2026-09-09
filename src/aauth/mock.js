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
import { clearPersonTokens } from './person-token-store.js'

const DEFAULTS = () => ({
    // Auth token endpoint behaviour
    auto_approve: true,         // 200 + auth_token directly
    requirement: null,          // null | 'interaction' | 'approval' | 'clarification'
    clarification: null,        // markdown question to return
    // Person token endpoint behaviour — its own switch, so a test can
    // defer the person token while the auth token stays immediate.
    person_requirement: null,   // null | 'interaction' | 'approval'
    // Whether an agent that declared NO capabilities may be handed a
    // `requirement=interaction` 202. Default false = capabilities omitted
    // means unknown, and the deferred path stays open (§canDriveInteraction).
    // True matches Hellō's Wallet: undeclared is unreachable, 403
    // user_unreachable. Set it in any suite that stands in for production.
    require_capabilities: false,
    // Error injection
    error: null,                // applies to /aauth/token unless scoped
    error_endpoint: null,       // restrict error to a specific endpoint
    // Token shape overrides
    token_lifetime: 3600,
    claims: null,               // identity claims to merge into auth_token
    r3_grants: null,            // { granted, per_call } override
    tenant: null,               // stamped on issued person tokens
    // Signing policy
    //   -11 requires content-digest + content-type coverage on bodies sent
    //   to a PS endpoint. Set false for clients that have not cut over.
    require_body_signing: true,
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
    clearPersonTokens()
}

export const get = async (req, res) => {
    return res.send(CONFIG)
}

export const put = async (req, res) => {
    const body = req.body || {}
    const next = { ...CONFIG }
    const passthrough = [
        'auto_approve', 'requirement', 'clarification', 'person_requirement',
        'require_capabilities',
        'error', 'error_endpoint',
        'token_lifetime', 'claims', 'r3_grants', 'tenant',
        'require_body_signing',
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
