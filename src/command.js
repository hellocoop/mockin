// command.js -- OP Command generation and verification

import { randomUUID } from 'crypto'
import sign from './sign.js'
import { ISSUER } from './config.js'

export const mock = async ( req, res ) => {

    const aud = req.query.client_id || 'test-app'
    const options = {
        header: {
            typ: 'command+jwt'
        }
    }

    const payload = {
        iss: ISSUER,
        aud,
        command: 'metadata',
        tenant: 'personal',
        jti: randomUUID(),
    }

    const command_token = await sign( payload, options );
    return res.send( {command_token} );
}