// aauth/state.js — in-memory pending authorization request state

const pendingRequests = new Map()

export function createPendingRequest(requestTicket, data) {
    pendingRequests.set(requestTicket, {
        ...data,
        status: 'pending',
        created: Date.now(),
    })
}

export function getPendingByRequestTicket(requestTicket) {
    return pendingRequests.get(requestTicket)
}

export function getPendingByInteractionTicket(interactionTicket) {
    for (const [requestTicket, data] of pendingRequests) {
        if (data.interaction_ticket === interactionTicket) {
            return { requestTicket, ...data }
        }
    }
    return null
}

export function updatePendingRequest(requestTicket, updates) {
    const existing = pendingRequests.get(requestTicket)
    if (!existing) return false
    pendingRequests.set(requestTicket, { ...existing, ...updates })
    return true
}

export function clearPendingRequests() {
    pendingRequests.clear()
}
