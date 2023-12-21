// mock.js

const { users } = await import('./users.js')

console.log('mock.js', {users})

let MOCK = {}
export default MOCK

const validMocks = new Set([
    'authorize',
    'introspection',
    'invite',
    'token',
    'user',
    'userinfo',
])

const validStatus = new Set([
    200,
    202,
    400,
    401,
    403,
    404,
    405,
    500,
    503,
])

const validErrors = new Set([
    'access_denied',
    'invalid_client',
    'invalid_grant',
    'invalid_request',
    'invalid_request',
    'invalid_scope',    
    'server_error',
    'temporarily_unavailable',
    'unauthorized_client',
    'unsupported_grant_type',
    'unsupported_response_type',
])

export const get = async ( req, res ) => {
    return res.send({MOCK})
}

const getUsers = async ( req, res ) => {
    console.log('mock.js', {users})
    return res.send({users})
}
export { getUsers as users }


export const put = async ( req, res ) => {
    const mock = req.params?.mock
    if (!validMocks.has(mock))
        return res.status(404).send({error:`"${mock}" is not a recognized parameter`})
    
    const status = Number(req?.query?.status)
    if (status) {
        if (validStatus.has(status))
            MOCK[mock] = {...MOCK[mock], ...{status}}
        else 
            return res.status(404).send({error:`"${status}" is not a valid status value`})
    }
    const error = req?.query?.error
    if (error) {
        if (validErrors.has(error))
            MOCK[mock] = {...MOCK[mock], ...{error}}
        else 
            return res.status(404).send({error:`"${error}" is not a valid error value`})
    }
    if (req.query)
        MOCK[mock] = {...MOCK[mock], ...req.query}
    if (req.body)
        MOCK[mock] = {...MOCK[mock], ...req.body}
    return res.send({MOCK})
}

export const user = async ( req, res ) => {
    const user = Number(req.params.user)
    if (user !== 0 || user > users.length ) 
        return res.status(404).send({error:`"${user}" is not a valid user`})
    MOCK.claims = users[user]
    return res.send({MOCK})
}

const del = async ( req, res ) => {
    const mock = req.params?.mock
    if (!mock)
        MOCK = {}
    else if (MOCK[mock])
        delete MOCK[mock]
    else if (!mocks.has(mock))
        return res.status(404).send({error:`"${mock}" is not a recognized parameter`})
    return res.send({MOCK})
}

export { del as delete }