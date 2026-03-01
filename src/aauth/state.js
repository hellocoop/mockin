// aauth/state.js — in-memory pending authorization request state

import { randomBytes } from 'crypto'

const pendingRequests = new Map()

function generateId() {
    return randomBytes(12).toString('base64url')
}

function generateCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    let code = ''
    const bytes = randomBytes(8)
    for (let i = 0; i < 8; i++) {
        code += chars[bytes[i] % chars.length]
    }
    return code
}

export function createPendingRequest(data) {
    const id = generateId()
    const code = generateCode()
    pendingRequests.set(id, {
        ...data,
        code,
        status: 'pending',
        created: Date.now(),
    })
    return { id, code }
}

export function getPendingById(id) {
    return pendingRequests.get(id)
}

export function getPendingByCode(code) {
    for (const [id, data] of pendingRequests) {
        if (data.code === code) {
            return { id, ...data }
        }
    }
    return null
}

export function updatePendingRequest(id, updates) {
    const existing = pendingRequests.get(id)
    if (!existing) return false
    pendingRequests.set(id, { ...existing, ...updates })
    return true
}

export function clearPendingRequests() {
    pendingRequests.clear()
}
