// aauth/state.js — in-memory pending authorization request state.
//
// A pending request represents work the PS has deferred (interaction,
// approval, or clarification). In auto-approve mode mockin never creates
// these; in deferred mode it does and resolves on the next poll.

import { randomBytes } from 'crypto'

const pending = new Map()

const generateId = () => randomBytes(12).toString('base64url')

const generateCode = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    const bytes = randomBytes(8)
    let code = ''
    for (let i = 0; i < 8; i++) code += chars[bytes[i] % chars.length]
    return code
}

export function createPending(data) {
    const id = generateId()
    const code = generateCode()
    pending.set(id, {
        id,
        code,
        status: 'pending',
        created: Date.now(),
        ...data,
    })
    return { id, code }
}

export function getPending(id) {
    return pending.get(id) || null
}

export function getPendingByCode(code) {
    for (const entry of pending.values()) {
        if (entry.code === code) return entry
    }
    return null
}

export function updatePending(id, updates) {
    const existing = pending.get(id)
    if (!existing) return false
    pending.set(id, { ...existing, ...updates })
    return true
}

export function deletePending(id) {
    return pending.delete(id)
}

export function clearPendingRequests() {
    pending.clear()
}
