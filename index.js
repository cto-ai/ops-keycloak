import qs from 'querystring'
import { once, on } from 'events'
import { createServer } from 'http'
import Keycloak from 'keycloak-connect'
import open from 'open'
import got from 'got'
import uuid from 'uuid'
import jwt from 'jsonwebtoken'
import createDebug from 'debug'

const debug = createDebug('ops:local-config')

const parse = (urlPath) => new URL(`x://${urlPath}`)

keycloak.validate = validate
keycloak.identity = identity

export default keycloak
export function validate ({ accessToken, idToken, refreshToken } = {}) {
  if (!accessToken) throw Error(ERR_MISSING_ACCESS_TOKEN)
  if (!idToken) throw Error(ERR_MISSING_ID_TOKEN)
  if (!refreshToken) throw Error(ERR_MISSING_REFRESH_TOKEN)
  const { exp } = jwt.decode(refreshToken)
  return Math.floor(Date.now() / 1000) < exp
}
export function identity ({ idToken } = {}) {
  if (!idToken) throw Error(ERR_MISSING_ID_TOKEN)
  const info = jwt.decode(idToken)
  return {
    id: info.sub,
    username: info.preferred_username,
    email: info.email
  }
}
export const ERR_NO_PORTS = 'None of keycloaks allowed ports can be bound to'
export const ERR_PAGE = (page) => `pages.${page} must be a buffer`
export const ERR_REALM = 'realm is required'
export const ERR_URL = 'url is required'
export const ERR_ID = 'id is required'
export const ERR_INVALID_RESPONSE = 'Invalid response from keycloak server'
export const ERR_MISSING_ACCESS_TOKEN = 'Access token is missing'
export const ERR_MISSING_REFRESH_TOKEN = 'Refresh token is missing'
export const ERR_MISSING_ID_TOKEN = 'Id token is missing'
export const ERR_MISSING_SESSION_STATE = 'Session state is missing'
export const ERR_BACKEND_SIGNIN = 'Backend mode signin method must be passed user and password'
export const ERR_BACKEND_METHOD_NOT_SUPPORTED = (method) => {
  return `${method} is not supported in backend mode`
}

class Granter extends Keycloak {
  constructor (config) {
    super({ store: new Map(), scope: 'openid' }, config)
  }

  storeGrant () { /* no op */ }
  async convert (data) {
    const grant = await this.getGrant({
      headers: {},
      session: { 'keycloak-token': data }
    })
    return {
      accessToken: grant.access_token.token,
      refreshToken: grant.refresh_token.token,
      idToken: grant.id_token.token,
      sessionState: grant.access_token.content.session_state
    }
  }
}

const dbg = (api) => {
  if (debug.enabled === false) return api
  for (const [k, fn] of Object.entries(api)) {
    api[k] = async (...args) => {
      try {
        return await fn(...args)
      } catch (err) {
        debug(err)
        throw err
      }
    }
  }
  return api
}

function keycloak ({ pages = {}, realm, url, id, backend = false } = {}) {
  if (!realm) throw Error(ERR_REALM)
  if (!url) throw Error(ERR_URL)
  if (!id) throw Error(ERR_ID)

  const config = {
    realm,
    'auth-server-url': url,
    resource: id,
    'ssl-required': 'external', // TODO: confirm: does not appear to be used in any dep
    'public-client': true, // ops-keycloak supports public clients only
    'confidential-port': 0 // TODO: confirm: does not appear to be used in any dep
  }

  const granter = new Granter(config)
  const endpoint = '/callback'
  const tokensUrl = `${url}/realms/${realm}/protocol/openid-connect/token`
  const passwordsUrl = `${url}/realms/${realm}/account/password`
  const registrationsUrl = `${url}/realms/${realm}/protocol/openid-connect/registrations`
  const resetsUrl = `${url}/realms/${realm}/login-actions/reset-credentials`
  const loginsUrl = `${url}/realms/${realm}/protocol/openid-connect/auth`
  const logoutsUrl = `${url}/realms/${realm}/protocol/openid-connect/logout`

  if (backend) {
    return dbg({
      refresh,
      signout,
      async signin ({ user, password } = {}) {
        if (!user || !password) throw Error(ERR_BACKEND_SIGNIN)
        return signin({ user, password })
      },
      validate,
      identity,
      async signup () { throw Error(ERR_BACKEND_METHOD_NOT_SUPPORTED('signup')) },
      reset () { throw Error(ERR_BACKEND_METHOD_NOT_SUPPORTED('reset')) }
    })
  }

  for (const page of ['signup', 'signin', 'error']) {
    if (Buffer.isBuffer(pages[page])) continue
    throw Error(ERR_PAGE(page))
  }

  async function auth (navTo, page) {
    const server = createServer()
    const ports = [10234, 28751, 38179, 41976, 49164]
    while (true) {
      server.listen(ports.shift())
      const [err] = await Promise.race([once(server, 'error'), once(server, 'listening')])
      if (!err) break
      if (ports.length === 0) throw Error(ERR_NO_PORTS)
    }

    try {
      const { port } = server.address()
      const redir = `http://localhost:${port}${endpoint}`
      const params = qs.stringify({
        client_id: id,
        redirect_uri: redir,
        response_type: 'code',
        scope: 'openid token',
        nonce: uuid(),
        state: uuid()
      })
      open(`${navTo}?${params}`)
      for await (const [req, res] of on(server, 'request')) {
        if (req.method !== 'GET') {
          res.statusCode = 400
          res.end(pages.error)
          continue
        }
        const { pathname, searchParams } = parse(req.url)

        if (pathname !== endpoint) {
          res.statusCode = 404
          res.end(pages.error)
          continue
        }
        const code = searchParams.get('code')

        if (!code) {
          res.statusCode = 400
          res.end(pages.error)
          continue
        }
        const data = qs.stringify({
          code: code,
          grant_type: 'authorization_code',
          client_id: id,
          redirect_uri: redir
        })
        const result = await got.post(tokensUrl, {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': data.length
          },
          body: data
        }).json()
        if (!result.access_token || !result.refresh_token || !result.id_token || !result.session_state) {
          res.statusCode = 400
          const finish = once(res, 'finish')
          res.end(pages.error)
          await finish
          throw Error(ERR_INVALID_RESPONSE)
        }
        const grant = await granter.convert(result)
        const finish = once(res, 'finish')
        res.end(page)
        await finish
        return grant
      }
    /* c8 ignore next */
    } finally {
      server.close()
      await once(server, 'close')
    }
  }

  async function signup () {
    const tokens = await auth(registrationsUrl, pages.signup)
    return tokens
  }

  async function signin ({ user, password } = {}) {
    const interactive = !user || !password
    if (interactive) {
      const tokens = await auth(loginsUrl, pages.signin)
      return tokens
    }
    debug('getting token from password grant')
    const data = qs.stringify({
      grant_type: 'password',
      client_id: id,
      username: user,
      password,
      scope: 'openid'
    })
    const result = await got.post(tokensUrl, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': data.length
      },
      body: data
    }).json()

    if (!result.access_token || !result.refresh_token || !result.id_token || !result.session_state) {
      throw Error(ERR_INVALID_RESPONSE)
    }

    return {
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      idToken: result.id_token,
      sessionState: result.session_state
    }
  }

  async function refresh (tokens = {}) {
    debug('Starting to refresh access token')
    const { sessionState, refreshToken } = tokens
    if (!refreshToken) throw Error(ERR_MISSING_REFRESH_TOKEN)
    if (!sessionState) throw Error(ERR_MISSING_SESSION_STATE)
    const data = qs.stringify({
      grant_type: 'refresh_token',
      client_id: id,
      refresh_token: refreshToken
    })
    const result = await got.post(tokensUrl, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': data.length
      },
      body: data
    }).json()

    if (!result.access_token || !result.refresh_token || !result.id_token) {
      throw Error(ERR_INVALID_RESPONSE)
    }

    debug('Successfully refreshed access token')

    return {
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      idToken: result.id_token,
      sessionState: sessionState
    }
  }

  async function signout (tokens = {}) {
    const { accessToken, refreshToken } = tokens
    if (!accessToken) throw Error(ERR_MISSING_ACCESS_TOKEN)
    if (!refreshToken) throw Error(ERR_MISSING_REFRESH_TOKEN)
    const data = qs.stringify({
      client_id: id,
      refresh_token: refreshToken
    })
    await got.post(logoutsUrl, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: accessToken,
        'Content-Length': data.length
      },
      body: data
    }).json()
  }

  function reset (opts = {}) {
    const { signedIn = false } = opts
    open(signedIn ? passwordsUrl : resetsUrl)
  }

  return dbg({
    signup, signin, signout, validate, identity, refresh, reset
  })
}
