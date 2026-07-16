// command.js -- OP Command generation and verification
// mints OpenID Provider Commands draft-02 command tokens

import { randomUUID } from 'crypto'
import sign from './sign.js'
import { ISSUER } from './config.js'

export const mock = async ( req, res ) => {

    const client_id = req.query.client_id || 'test-app'
    // draft-02: aud is the RP's command endpoint URL
    // falls back to client_id for backwards compatibility
    const aud = req.query.aud || client_id
    const command = req.query.command || 'metadata'
    const options = {
        header: {
            typ: 'command+jwt'
        }
    }

    const payload = {
        iss: ISSUER,
        aud,
        client_id,
        command,
        tenant: req.query.tenant || 'personal',
        jti: randomUUID(),
    }
    // account commands carry a sub; tenant commands must not
    if (req.query.sub)
        payload.sub = req.query.sub

    const command_token = await sign( payload, options );
    return res.send( {command_token} );
}
