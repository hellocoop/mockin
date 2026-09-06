// RFC 7636 S256 code_verifier / code_challenge pair for tests.
import { createHash, randomBytes } from 'crypto'

export default async function pkceChallenge() {
    const code_verifier = randomBytes(32).toString('base64url')
    const code_challenge = createHash('sha256').update(code_verifier).digest('base64url')
    return { code_verifier, code_challenge, code_challenge_method: 'S256' }
}
