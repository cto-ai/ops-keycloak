import fs from 'fs'
import qs from 'querystring'
import { fileURLToPath } from 'url'
import { join, dirname } from 'path'
import { createServer } from 'http'
import { once } from 'events'
import { promisify } from 'util'
import { test, mockalicious } from 'tapx'
import { when } from 'nonsynchronous'
import got from 'got'
import jwt from 'jsonwebtoken'
import keycloak, {
  ERR_PAGE,
  ERR_REALM,
  ERR_URL,
  ERR_ID,
  ERR_INVALID_RESPONSE,
  ERR_MISSING_ACCESS_TOKEN,
  ERR_MISSING_REFRESH_TOKEN,
  ERR_MISSING_ID_TOKEN,
  ERR_MISSING_SESSION_STATE,
  ERR_BACKEND_SIGNIN,
  ERR_BACKEND_METHOD_NOT_SUPPORTED
} from '../index.js'
const { readFile } = fs.promises

const load = mockalicious(import.meta.url)
const __dirname = dirname(fileURLToPath(import.meta.url))

const certs = async (server) => {
  const [req, res] = await once(server, 'request')
  if (req.url !== '/realms/test/protocol/openid-connect/certs') {
    throw Error('developer error, next request is assumed to be cert request')
  }
  const certs = {
    keys: [
      {
        kid: 'testkid',
        kty: 'RSA',
        n: 'y9u67ytpLD-RiNV54IPGC_ceVDgYAYDzKJFjQCyYzA6fjg49-fIWQ2fNj-wHBiJbzYHS9XTjq9jffFkwx-OLlmMoYqrU2_t2yt7306XTuKnBh-RIlzNVy7CN-sg84s_06zPpOSus3kv1DZJ9U13Qq7jrMzf_mYot2gt5gtu0EJziAMQnpXd75fsoxhYYgMaF_HIax670bRYMeXTX9gzJU9AauuDcai7taAW0Th3dgxWXgspWNjtAzU7TPORWNc4MgupXdNwmSxvvy3ZfbCIOCk5kgcz3Yw6H-R04YMZmQu07n8xo4Z9dgrLTDMGSwixA5-F9UbJpzlQgz45UPpMgIq0JLPSIOlBTsPCDn6mjFQm58C1VKDidB0FEZGGv-YbvqNhuOxShggmvyohE9RYqWsakJg6ep7ZT0Shcjic36gRFDMuRZUS4Zkg8Q2u3C50qRUEPhdjuN4w-q7CTLItCmVJ_zLkUXmdG7470pMX05pqaqxy-wm3bYX09fFTtrOmqY8e4GRiQEH3AVAfdKM09RVbVpgm9JhB5xuDNsgbGT4RrasckDvQziPus7xeeD7sLNozcmSouISGJC9NgcwCDkwBHBY-Be1T6pF_tL6SwxFxxulfAjYghRl6MRlEf-FMUsDRqSSio2bH09KvpweqfH-m0EkQn5dv6eJNe19tKNWs',
        e: 'AQAB',
        alg: 'RS256',
        use: 'sig',
        x5c: [
          'MIIClTCCAX0CBgFqXW+EVzANBgkhqkiG9w0BAQsFADAOMQwwCgYDVQQDDANvcHMwHhcNMTkwNDI3MDYxNDEwWhcNMjkwNDI3MDYxNTUwWjAOMQwwCgYDVQQDDANvcHMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRttSSoChUBG+P0eROYnxl/FJNBKzQEGkzM7AjML+VNaX+YQnr1tkWfUQ/6rExDAnfvDMod2eI892DoUHmkUqi50PGs+WN32QYhI2gYDL23SVkOeUFDpYvqgm3ZAgTjk5InM1LL1dVtoq5qoXCCDxssI3tqxuBTxkr1tupbMHKKgCKUXWwdiWH35dB08XDaxzQOa9lR1HhFOK1CQnM0ecB+pae0KK/z7MeTQtJc905qOG4D7Q/udmlierj7W1RgAI1P8mcX+MiF6WIA//5XziOREBiRxBpDvJWHDkkhPJNA+a74qODuSLhJbBI9WOg6ks4JsyoTNfxpdai/ERhmebBAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAk33ZmqFlk4rrhzWoVWNyYMUt8a4ng74AB5gELFi75PfZornCC0XHq0WgE/+fr5ApZ6XlltvIcXww1Vl3SrYMUybWHV1eihsZkl2it7mLDHc1dfE/xQIZsdgxLjimF+xyyRfCN0gXEIAvbVHVwuDWO/5UMkxiBt0Dyu1CfwadjHlaW8ThI2sGeC8+lO9ZeX04jRRY3vOASs7OxTPwxZf3x/skuhKRoWKxAD5ETyDVPZRtepwTasWUkuGGQrB4vnFYE1ywEgoqwOlXfdDT39yK7LRKpALoMYGe/Y3/YBgjwkNVDCetontaIUuas+xFlcRHEXRsOm0L1C+mj2u4LDM3Q='
        ],
        x5t: 'b_ja9xvXJ3lx2L1RmAz5fSERMp8',
        'x5t#S256': 'te4GImU8Z32xvD3P_gpzVLURJ73F_iOBNHl_Im2mODRQ'
      }
    ]
  }
  res.setHeader('content-type', 'application/json')
  res.end(JSON.stringify(certs))
}

test('option validation', async ({ throws, doesNotThrow }) => {
  throws(() => keycloak(), Error(ERR_REALM))
  throws(() => keycloak({ realm: 'test' }), Error(ERR_URL))
  throws(() => keycloak({ realm: 'test', url: 'http://localhost:8080' }), Error(ERR_ID))
  throws(() => keycloak({ realm: 'test', url: 'http://localhost:8080', id: 'test' }), Error(ERR_PAGE('signup')))
  throws(() => keycloak({
    pages: {},
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test'
  }), Error(ERR_PAGE('signup')))
  throws(() => keycloak({
    pages: { signup: 'test' },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test'
  }), Error(ERR_PAGE('signup')))
  throws(() => keycloak({
    pages: { signup: Buffer.from('test') },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test'
  }), Error(ERR_PAGE('signin')))
  throws(() => keycloak({
    pages: { signup: Buffer.from('test'), signin: 'test' },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test'
  }), Error(ERR_PAGE('signin')))
  throws(() => keycloak({
    pages: { signup: Buffer.from('test'), signin: Buffer.from('test') },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test'
  }), Error(ERR_PAGE('error')))
  throws(() => keycloak({
    pages: { signup: Buffer.from('test'), signin: Buffer.from('test'), error: 'test' },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test'
  }), Error(ERR_PAGE('error')))
  doesNotThrow(() => keycloak({
    pages: { signup: Buffer.from('test'), signin: Buffer.from('test'), error: Buffer.from('test') },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test'
  }))
  throws(() => keycloak({
    backend: true,
    url: 'http://localhost:8080',
    id: 'test'
  }))
  throws(() => keycloak({
    backend: true,
    realm: 'test',
    id: 'test'
  }))
  throws(() => keycloak({
    backend: true,
    realm: 'test',
    url: 'http://localhost:8080'
  }))
  doesNotThrow(() => keycloak({
    backend: true,
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test'
  }))
})

test('validate', async ({ is, throws }) => {
  const sig = await readFile(join(__dirname, 'fixtures', 'private.pem'))
  const validToken = jwt.sign({
    jti: 'ea5f888e-61dc-4369-a910-95617e12a5c1',
    nbf: 0,
    iss: 'http://localhost:8080/realms/test',
    sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
    typ: 'Bearer',
    azp: 'test-id',
    nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
    session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
    acr: '1',
    scope: 'openid email profile',
    email_verified: false,
    name: 'test test',
    preferred_username: 'test',
    given_name: 'test',
    family_name: 'test',
    email: 'test@test.com'
  }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } })

  const invalidToken = jwt.sign({
    jti: 'ea5f888e-61dc-4369-a910-95617e12a5c1',
    nbf: 0,
    iss: 'http://localhost:8080/realms/test',
    sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
    typ: 'Bearer',
    azp: 'test-id',
    nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
    session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
    acr: '1',
    scope: 'openid email profile',
    email_verified: false,
    name: 'test test',
    preferred_username: 'test',
    given_name: 'test',
    family_name: 'test',
    email: 'test@test.com'
  }, sig, { algorithm: 'RS256', expiresIn: 0, header: { kid: 'testkid' } })
  is(keycloak.validate({
    accessToken: validToken,
    refreshToken: validToken,
    idToken: validToken,
    sessionState: validToken
  }), true)

  is(keycloak.validate({
    accessToken: validToken,
    refreshToken: invalidToken,
    idToken: validToken,
    sessionState: validToken
  }), false)

  throws(() => keycloak.validate(), Error(ERR_MISSING_ACCESS_TOKEN))
  throws(() => keycloak.validate({ accessToken: validToken }), Error(ERR_MISSING_ID_TOKEN))
  throws(() => keycloak.validate({ accessToken: validToken, idToken: validToken }), Error(ERR_MISSING_REFRESH_TOKEN))

  const instance = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  })

  is(instance.validate({
    accessToken: validToken,
    refreshToken: validToken,
    idToken: validToken,
    sessionState: validToken
  }), true)

  is(instance.validate({
    accessToken: validToken,
    refreshToken: invalidToken,
    idToken: validToken,
    sessionState: validToken
  }), false)

  throws(() => instance.validate(), Error(ERR_MISSING_ACCESS_TOKEN))
  throws(() => instance.validate({ accessToken: validToken }), Error(ERR_MISSING_ID_TOKEN))
  throws(() => instance.validate({ accessToken: validToken, idToken: validToken }), Error(ERR_MISSING_REFRESH_TOKEN))

  const backendInstance = keycloak({
    backend: true,
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  })

  is(backendInstance.validate({
    accessToken: validToken,
    refreshToken: validToken,
    idToken: validToken,
    sessionState: validToken
  }), true)

  is(backendInstance.validate({
    accessToken: validToken,
    refreshToken: invalidToken,
    idToken: validToken,
    sessionState: validToken
  }), false)

  throws(() => backendInstance.validate(), Error(ERR_MISSING_ACCESS_TOKEN))
  throws(() => backendInstance.validate({ accessToken: validToken }), Error(ERR_MISSING_ID_TOKEN))
  throws(() => backendInstance.validate({ accessToken: validToken, idToken: validToken }), Error(ERR_MISSING_REFRESH_TOKEN))
})

test('signup', async ({ is, ok, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const context = {}
  const until = when()
  const keycloak = await load('..', {
    open (url) {
      context.url = url
      until()
    }
  })

  const transaction = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: service,
    id: 'test-id'
  }).signup()
  await until.done()
  const { pathname, searchParams } = new URL(context.url)
  const redirect = decodeURIComponent(searchParams.get('redirect_uri'))
  is(pathname, '/realms/test/protocol/openid-connect/registrations')
  is(decodeURIComponent(searchParams.get('client_id')), 'test-id')
  is(decodeURIComponent(searchParams.get('response_type')), 'code')
  is(decodeURIComponent(searchParams.get('scope')), 'openid token')
  ok(searchParams.has('state'))
  const get = got(`${redirect}?code=test`)

  const [req, res] = await once(server, 'request')
  is(req.url, '/realms/test/protocol/openid-connect/token')
  const { headers } = req
  is(headers['content-type'], 'application/x-www-form-urlencoded')
  is(headers['content-length'], '112')
  const [data] = await once(req, 'data')
  const body = qs.parse(data.toString())
  is(body.code, 'test')
  is(body.grant_type, 'authorization_code')
  is(body.client_id, 'test-id')
  res.setHeader('content-type', 'application/json')
  const sig = await readFile(join(__dirname, 'fixtures', 'private.pem'))
  const response = {
    access_token: jwt.sign({
      jti: 'ea5f888e-61dc-4369-a910-95617e12a5c1',
      nbf: 0,
      iss: `${service}/realms/test`,
      sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
      typ: 'Bearer',
      azp: 'test-id',
      nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
      session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
      acr: '1',
      scope: 'openid email profile',
      email_verified: false,
      name: 'test test',
      preferred_username: 'test',
      given_name: 'test',
      family_name: 'test',
      email: 'test@test.com'
    }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } }),
    expires_in: 2592000,
    refresh_expires_in: 2592000,
    refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4MDgwNTg2NC05NzYxLTRmZmUtOGVkMC00ZjkwYmNiYjkyNGQifQ.eyJqdGkiOiI0NWUxMTFiMC03Njg4LTQ2NDYtYTg5Mi0xOWViNjUzM2JhNTYiLCJleHAiOjE2MTU1MTA1NzIsIm5iZiI6MCwiaWF0IjoxNjEyOTE4NTcyLCJpc3MiOiJodHRwczovL2N0by5haS9hdXRoL3JlYWxtcy9vcHMiLCJhdWQiOiJodHRwczovL2N0by5haS9hdXRoL3JlYWxtcy9vcHMiLCJzdWIiOiJkN2I1NTgxMC0yMzliLTQ4MzctYmQ0ZC0xMjVhNDBjOWExZmMiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoib3BzLWNsaSIsIm5vbmNlIjoiYjJjODJiMzAtNmIzYS0xMWViLWFlZmItZGIwZWFkYzk2ZjJlIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiNDVjZGMxZGYtZjhlYi0hsen66MDD45keFZ4WpoMBdqRySV3R0veviuw1qZSbzk9Uv20hyuX5_-L-oMc3Vn3SxS5xSqOjtTQCyHQK2Mn1Ow0oXA2zHmPJwNY8BMHn54LRxE-iP97cZpnu-VArI8MYc6lCZ2g_eRSb-IycWU8_qhVWsxyPAZgCGQ4tT1yTHO-dckHlFcTIYskXNjcH0n7KgDxbf8TrU9bxIalom31fAJHwpN12gc9s3DPZbmkPa1w5VGT2X8bjFiwl5pwE5yNIeKKQ',
    token_type: 'bearer',
    id_token: jwt.sign({
      jti: 'db34922c-b52e-47b7-8b54-d6a2e8afbc1f',
      nbf: 0,
      iss: `${service}/realms/test`,
      sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
      typ: 'ID',
      azp: 'test-id',
      aud: 'test-id',
      nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
      session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
      acr: '1',
      email_verified: false,
      name: 'test test',
      preferred_username: 'test',
      given_name: 'test',
      family_name: 'test',
      email: 'test@test.com'
    }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } }),
    'not-before-policy': 0,
    session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
    scope: 'openid email profile'
  }
  res.end(JSON.stringify(response))
  await certs(server)
  await certs(server)
  const page = await get
  is(page.body, 'signup')
  const result = await transaction
  ok(result.accessToken)
  ok(result.refreshToken)
  ok(result.idToken)
  ok(result.sessionState)
  server.close()
})

test('signin (interactive)', async ({ is, ok, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const context = {}
  const until = when()
  const keycloak = await load('..', {
    open (url) {
      context.url = url
      until()
    }
  })
  const transaction = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: service,
    id: 'test-id'
  }).signin()
  await until.done()
  const { pathname, searchParams } = new URL(context.url)
  const redirect = decodeURIComponent(searchParams.get('redirect_uri'))
  is(pathname, '/realms/test/protocol/openid-connect/auth')
  is(decodeURIComponent(searchParams.get('client_id')), 'test-id')
  is(decodeURIComponent(searchParams.get('response_type')), 'code')
  is(decodeURIComponent(searchParams.get('scope')), 'openid token')
  ok(searchParams.has('state'))
  const get = got(`${redirect}?code=test`)

  const [req, res] = await once(server, 'request')
  is(req.url, '/realms/test/protocol/openid-connect/token')
  const { headers } = req
  is(headers['content-type'], 'application/x-www-form-urlencoded')
  is(headers['content-length'], '112')
  const [data] = await once(req, 'data')
  const body = qs.parse(data.toString())
  is(body.code, 'test')
  is(body.grant_type, 'authorization_code')
  is(body.client_id, 'test-id')
  res.setHeader('content-type', 'application/json')
  const sig = await readFile(join(__dirname, 'fixtures', 'private.pem'))
  const response = {
    access_token: jwt.sign({
      jti: 'ea5f888e-61dc-4369-a910-95617e12a5c1',
      nbf: 0,
      iss: `${service}/realms/test`,
      sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
      typ: 'Bearer',
      azp: 'test-id',
      nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
      session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
      acr: '1',
      scope: 'openid email profile',
      email_verified: false,
      name: 'test test',
      preferred_username: 'test',
      given_name: 'test',
      family_name: 'test',
      email: 'test@test.com'
    }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } }),
    expires_in: 2592000,
    refresh_expires_in: 2592000,
    refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4MDgwNTg2NC05NzYxLTRmZmUtOGVkMC00ZjkwYmNiYjkyNGQifQ.eyJqdGkiOiI0NWUxMTFiMC03Njg4LTQ2NDYtYTg5Mi0xOWViNjUzM2JhNTYiLCJleHAiOjE2MTU1MTA1NzIsIm5iZiI6MCwiaWF0IjoxNjEyOTE4NTcyLCJpc3MiOiJodHRwczovL2N0by5haS9hdXRoL3JlYWxtcy9vcHMiLCJhdWQiOiJodHRwczovL2N0by5haS9hdXRoL3JlYWxtcy9vcHMiLCJzdWIiOiJkN2I1NTgxMC0yMzliLTQ4MzctYmQ0ZC0xMjVhNDBjOWExZmMiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoib3BzLWNsaSIsIm5vbmNlIjoiYjJjODJiMzAtNmIzYS0xMWViLWFlZmItZGIwZWFkYzk2ZjJlIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiNDVjZGMxZGYtZjhlYi0hsen66MDD45keFZ4WpoMBdqRySV3R0veviuw1qZSbzk9Uv20hyuX5_-L-oMc3Vn3SxS5xSqOjtTQCyHQK2Mn1Ow0oXA2zHmPJwNY8BMHn54LRxE-iP97cZpnu-VArI8MYc6lCZ2g_eRSb-IycWU8_qhVWsxyPAZgCGQ4tT1yTHO-dckHlFcTIYskXNjcH0n7KgDxbf8TrU9bxIalom31fAJHwpN12gc9s3DPZbmkPa1w5VGT2X8bjFiwl5pwE5yNIeKKQ',
    token_type: 'bearer',
    id_token: jwt.sign({
      jti: 'db34922c-b52e-47b7-8b54-d6a2e8afbc1f',
      nbf: 0,
      iss: `${service}/realms/test`,
      sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
      typ: 'ID',
      azp: 'test-id',
      aud: 'test-id',
      nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
      session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
      acr: '1',
      email_verified: false,
      name: 'test test',
      preferred_username: 'test',
      given_name: 'test',
      family_name: 'test',
      email: 'test@test.com'
    }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } }),
    'not-before-policy': 0,
    session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
    scope: 'openid email profile'
  }
  res.end(JSON.stringify(response))
  await certs(server)
  await certs(server)
  const page = await get
  is(page.body, 'signin')
  const result = await transaction
  ok(result.accessToken)
  ok(result.refreshToken)
  ok(result.idToken)
  ok(result.sessionState)
  server.close()
})

test('signin (user, password)', async ({ is, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const transaction = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: service,
    id: 'test-id'
  }).signin({ user: 'test', password: 'pwtest' })

  const [req, res] = await once(server, 'request')
  is(req.url, '/realms/test/protocol/openid-connect/token')
  const { headers } = req
  is(headers['content-type'], 'application/x-www-form-urlencoded')
  is(headers['content-length'], '80')
  const [data] = await once(req, 'data')
  const body = qs.parse(data.toString())
  is(body.grant_type, 'password')
  is(body.username, 'test')
  is(body.password, 'pwtest')
  is(body.client_id, 'test-id')
  is(body.scope, 'openid')
  res.setHeader('content-type', 'application/json')

  res.end(JSON.stringify({
    access_token: 'at',
    refresh_token: 'rt',
    id_token: 'it',
    session_state: 'ss'
  }))

  const result = await transaction
  is(result.accessToken, 'at')
  is(result.refreshToken, 'rt')
  is(result.idToken, 'it')
  is(result.sessionState, 'ss')
  server.close()
})

test('backend mode signin (user, password)', async ({ is, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const transaction = keycloak({
    backend: true,
    realm: 'test',
    url: service,
    id: 'test-id'
  }).signin({ user: 'test', password: 'pwtest' })

  const [req, res] = await once(server, 'request')
  is(req.url, '/realms/test/protocol/openid-connect/token')
  const { headers } = req
  is(headers['content-type'], 'application/x-www-form-urlencoded')
  is(headers['content-length'], '80')
  const [data] = await once(req, 'data')
  const body = qs.parse(data.toString())
  is(body.grant_type, 'password')
  is(body.username, 'test')
  is(body.password, 'pwtest')
  is(body.client_id, 'test-id')
  is(body.scope, 'openid')
  res.setHeader('content-type', 'application/json')

  res.end(JSON.stringify({
    access_token: 'at',
    refresh_token: 'rt',
    id_token: 'it',
    session_state: 'ss'
  }))

  const result = await transaction
  is(result.accessToken, 'at')
  is(result.refreshToken, 'rt')
  is(result.idToken, 'it')
  is(result.sessionState, 'ss')
  server.close()
})

test('signout input validation', async ({ rejects, teardown }) => {
  await rejects(keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  }).signout(), Error(ERR_MISSING_ACCESS_TOKEN))
  await rejects(keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  }).signout({ accessToken: 'at' }), Error(ERR_MISSING_REFRESH_TOKEN))
})

test('signout', async ({ is, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const transaction = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: service,
    id: 'test-id'
  }).signout({
    accessToken: 'at',
    refreshToken: 'rt',
    idToken: 'it',
    sessionState: 'ss'
  })

  const [req, res] = await once(server, 'request')
  is(req.url, '/realms/test/protocol/openid-connect/logout')
  const { headers } = req
  is(headers['content-type'], 'application/x-www-form-urlencoded')
  is(headers['content-length'], '34')
  const [data] = await once(req, 'data')
  const body = qs.parse(data.toString())
  is(body.client_id, 'test-id')
  is(body.refresh_token, 'rt')
  res.setHeader('content-type', 'application/json')
  res.end()
  await transaction
  server.close()
})

test('refresh input validation', async ({ rejects, teardown }) => {
  await rejects(keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  }).refresh(), Error(ERR_MISSING_REFRESH_TOKEN))
  await rejects(keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  }).refresh({ refreshToken: 'rt' }), Error(ERR_MISSING_SESSION_STATE))
})

test('refresh', async ({ is, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const transaction = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: service,
    id: 'test-id'
  }).refresh({
    accessToken: 'at',
    refreshToken: 'rt',
    idToken: 'it',
    sessionState: 'ss'
  })

  const [req, res] = await once(server, 'request')
  is(req.url, '/realms/test/protocol/openid-connect/token')
  const { headers } = req
  is(headers['content-type'], 'application/x-www-form-urlencoded')
  is(headers['content-length'], '59')
  const [data] = await once(req, 'data')
  const body = qs.parse(data.toString())
  is(body.grant_type, 'refresh_token')
  is(body.client_id, 'test-id')
  is(body.refresh_token, 'rt')
  res.end(JSON.stringify({
    access_token: 'nat',
    refresh_token: 'nrt',
    id_token: 'nit',
    session_state: 'SHOULD NOT BE STORED'
  }))

  const result = await transaction
  is(result.accessToken, 'nat')
  is(result.refreshToken, 'nrt')
  is(result.idToken, 'nit')
  is(result.sessionState, 'ss')
  server.close()
})

test('reset (signed in)', async ({ is, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const context = {}
  const until = when()
  const keycloak = await load('..', {
    open (url) {
      context.url = url
      until()
    }
  })
  const done = until.done()
  const transaction = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: service,
    id: 'test-id'
  }).reset({ signedIn: true })
  await done
  const { pathname } = new URL(context.url)
  is(pathname, '/realms/test/account/password')
  await transaction
  server.close()
})

test('reset (not signed in)', async ({ is, teardown }) => {
  {
    const server = createServer()
    teardown(() => server.close())
    await promisify(server.listen.bind(server))()
    const service = `http://localhost:${server.address().port}`
    const context = {}
    const until = when()
    const keycloak = await load('..', {
      open (url) {
        context.url = url
        until()
      }
    })
    const done = until.done()
    const transaction = keycloak({
      pages: {
        signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
      },
      realm: 'test',
      url: service,
      id: 'test-id'
    }).reset({ signedIn: false })
    await done
    const { pathname } = new URL(context.url)
    is(pathname, '/realms/test/login-actions/reset-credentials')
    await transaction
    server.close()
  }
  {
    const server = createServer()
    teardown(() => server.close())
    await promisify(server.listen.bind(server))()
    const service = `http://localhost:${server.address().port}`
    const context = {}
    const until = when()
    const keycloak = await load('..', {
      open (url) {
        context.url = url
        until()
      }
    })
    const done = until.done()
    const transaction = keycloak({
      pages: {
        signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
      },
      realm: 'test',
      url: service,
      id: 'test-id'
    }).reset()
    await done
    const { pathname } = new URL(context.url)
    is(pathname, '/realms/test/login-actions/reset-credentials')
    await transaction
    server.close()
  }
})

test('backend mode signup', async ({ rejects }) => {
  await rejects(() => keycloak({
    backend: true,
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  }).signup(), Error(ERR_BACKEND_METHOD_NOT_SUPPORTED('signup')))
})

test('backend mode reset', async ({ throws }) => {
  await throws(() => keycloak({
    backend: true,
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  }).reset(), Error(ERR_BACKEND_METHOD_NOT_SUPPORTED('reset')))
})

test('backend mode signin validation', async ({ rejects }) => {
  await rejects(() => keycloak({
    backend: true,
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  }).signin(), Error(ERR_BACKEND_SIGNIN))
})

test('invalid response for signin (user, password)', async ({ is, rejects, teardown }) => {
  const invalidResponses = [
    {},
    {
      session_state: 'ss'
    },
    {
      id_token: 'it',
      session_state: 'ss'
    },
    {
      refresh_token: 'rt',
      id_token: 'it',
      session_state: 'ss'
    }
  ]
  for (const invalidResponse of invalidResponses) {
    const server = createServer()
    teardown(() => server.close())
    await promisify(server.listen.bind(server))()
    const service = `http://localhost:${server.address().port}`
    const transaction = rejects(keycloak({
      pages: {
        signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
      },
      realm: 'test',
      url: service,
      id: 'test-id'
    }).signin({ user: 'test', password: 'pwtest' }), Error(ERR_INVALID_RESPONSE))

    const [req, res] = await once(server, 'request')
    is(req.url, '/realms/test/protocol/openid-connect/token')
    res.setHeader('content-type', 'application/json')

    res.end(JSON.stringify(invalidResponse))

    await transaction
    server.close()
  }
})

test('invalid response for refresh', async ({ is, rejects, teardown }) => {
  const invalidResponses = [
    {},
    {
      id_token: 'it',
      session_state: 'ss'
    },
    {
      refresh_token: 'rt',
      id_token: 'it'
    }
  ]
  for (const invalidResponse of invalidResponses) {
    const server = createServer()
    teardown(() => server.close())
    await promisify(server.listen.bind(server))()
    const service = `http://localhost:${server.address().port}`
    const transaction = rejects(keycloak({
      pages: {
        signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
      },
      realm: 'test',
      url: service,
      id: 'test-id'
    }).refresh({
      accessToken: 'at',
      refreshToken: 'rt',
      idToken: 'it',
      sessionState: 'ss'
    }), Error(ERR_INVALID_RESPONSE))

    const [req, res] = await once(server, 'request')

    is(req.url, '/realms/test/protocol/openid-connect/token')
    res.setHeader('content-type', 'application/json')

    res.end(JSON.stringify(invalidResponse))

    await transaction

    server.close()
  }
})

test('invalid response for signup', async ({ is, rejects, teardown }) => {
  const invalidResponses = [
    {},
    {
      session_state: 'ss'
    },
    {
      id_token: 'it',
      session_state: 'ss'
    },
    {
      refresh_token: 'rt',
      id_token: 'it',
      session_state: 'ss'
    }
  ]
  for (const invalidResponse of invalidResponses) {
    const server = createServer()
    teardown(() => server.close())
    await promisify(server.listen.bind(server))()
    const service = `http://localhost:${server.address().port}`
    const context = {}
    const until = when()
    const keycloak = await load('..', {
      open (url) {
        context.url = url
        until()
      }
    })

    const transaction = rejects(keycloak({
      pages: {
        signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
      },
      realm: 'test',
      url: service,
      id: 'test-id'
    }).signup())
    await until.done()
    const { pathname, searchParams } = new URL(context.url)
    const redirect = decodeURIComponent(searchParams.get('redirect_uri'))
    is(pathname, '/realms/test/protocol/openid-connect/registrations')
    const get = got(`${redirect}?code=test`, { throwHttpErrors: false })
    const [req, res] = await once(server, 'request')
    is(req.url, '/realms/test/protocol/openid-connect/token')
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify(invalidResponse))
    const { body, statusCode } = await get
    is(body, 'error')
    is(statusCode, 400)
    await transaction
    server.close()
  }
})

test('auth server not found responses', async ({ is, rejects, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const context = {}
  const until = when()
  const keycloak = await load('..', {
    open (url) {
      context.url = url
      until()
    }
  })

  const transaction = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: service,
    id: 'test-id'
  }).signup()
  await until.done()
  const { pathname, searchParams } = new URL(context.url)
  const redirect = decodeURIComponent(searchParams.get('redirect_uri'))
  is(pathname, '/realms/test/protocol/openid-connect/registrations')
  const { statusCode, body } = await got(`${redirect}/not-a-route/`, { throwHttpErrors: false })
  is(statusCode, 404)
  is(body, 'error')
  got(`${redirect}?code=test`)
  const [, res] = await once(server, 'request')
  res.setHeader('content-type', 'application/json')
  const sig = await readFile(join(__dirname, 'fixtures', 'private.pem'))
  const response = {
    access_token: jwt.sign({
      jti: 'ea5f888e-61dc-4369-a910-95617e12a5c1',
      nbf: 0,
      iss: `${service}/realms/test`,
      sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
      typ: 'Bearer',
      azp: 'test-id',
      nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
      session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
      acr: '1',
      scope: 'openid email profile',
      email_verified: false,
      name: 'test test',
      preferred_username: 'test',
      given_name: 'test',
      family_name: 'test',
      email: 'test@test.com'
    }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } }),
    expires_in: 2592000,
    refresh_expires_in: 2592000,
    refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4MDgwNTg2NC05NzYxLTRmZmUtOGVkMC00ZjkwYmNiYjkyNGQifQ.eyJqdGkiOiI0NWUxMTFiMC03Njg4LTQ2NDYtYTg5Mi0xOWViNjUzM2JhNTYiLCJleHAiOjE2MTU1MTA1NzIsIm5iZiI6MCwiaWF0IjoxNjEyOTE4NTcyLCJpc3MiOiJodHRwczovL2N0by5haS9hdXRoL3JlYWxtcy9vcHMiLCJhdWQiOiJodHRwczovL2N0by5haS9hdXRoL3JlYWxtcy9vcHMiLCJzdWIiOiJkN2I1NTgxMC0yMzliLTQ4MzctYmQ0ZC0xMjVhNDBjOWExZmMiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoib3BzLWNsaSIsIm5vbmNlIjoiYjJjODJiMzAtNmIzYS0xMWViLWFlZmItZGIwZWFkYzk2ZjJlIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiNDVjZGMxZGYtZjhlYi0hsen66MDD45keFZ4WpoMBdqRySV3R0veviuw1qZSbzk9Uv20hyuX5_-L-oMc3Vn3SxS5xSqOjtTQCyHQK2Mn1Ow0oXA2zHmPJwNY8BMHn54LRxE-iP97cZpnu-VArI8MYc6lCZ2g_eRSb-IycWU8_qhVWsxyPAZgCGQ4tT1yTHO-dckHlFcTIYskXNjcH0n7KgDxbf8TrU9bxIalom31fAJHwpN12gc9s3DPZbmkPa1w5VGT2X8bjFiwl5pwE5yNIeKKQ',
    token_type: 'bearer',
    id_token: jwt.sign({
      jti: 'db34922c-b52e-47b7-8b54-d6a2e8afbc1f',
      nbf: 0,
      iss: `${service}/realms/test`,
      sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
      typ: 'ID',
      azp: 'test-id',
      aud: 'test-id',
      nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
      session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
      acr: '1',
      email_verified: false,
      name: 'test test',
      preferred_username: 'test',
      given_name: 'test',
      family_name: 'test',
      email: 'test@test.com'
    }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } }),
    'not-before-policy': 0,
    session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
    scope: 'openid email profile'
  }
  res.end(JSON.stringify(response))
  await certs(server)
  await certs(server)
  await transaction
  server.close()
})

test('auth server bad request responses', async ({ is, rejects, teardown }) => {
  const server = createServer()
  teardown(() => server.close())
  await promisify(server.listen.bind(server))()
  const service = `http://localhost:${server.address().port}`
  const context = {}
  const until = when()
  const keycloak = await load('..', {
    open (url) {
      context.url = url
      until()
    }
  })

  const transaction = keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: service,
    id: 'test-id'
  }).signup()
  await until.done()
  const { pathname, searchParams } = new URL(context.url)
  const redirect = decodeURIComponent(searchParams.get('redirect_uri'))
  is(pathname, '/realms/test/protocol/openid-connect/registrations')
  {
    const { statusCode, body } = await got(`${redirect}`, { throwHttpErrors: false })
    is(statusCode, 400)
    is(body, 'error')
  }
  {
    const { statusCode, body } = await got.post(`${redirect}?code=test`, { throwHttpErrors: false })
    is(statusCode, 400)
    is(body, 'error')
  }
  got(`${redirect}?code=test`)
  const [, res] = await once(server, 'request')
  res.setHeader('content-type', 'application/json')
  const sig = await readFile(join(__dirname, 'fixtures', 'private.pem'))
  const response = {
    access_token: jwt.sign({
      jti: 'ea5f888e-61dc-4369-a910-95617e12a5c1',
      nbf: 0,
      iss: `${service}/realms/test`,
      sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
      typ: 'Bearer',
      azp: 'test-id',
      nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
      session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
      acr: '1',
      scope: 'openid email profile',
      email_verified: false,
      name: 'test test',
      preferred_username: 'test',
      given_name: 'test',
      family_name: 'test',
      email: 'test@test.com'
    }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } }),
    expires_in: 2592000,
    refresh_expires_in: 2592000,
    refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4MDgwNTg2NC05NzYxLTRmZmUtOGVkMC00ZjkwYmNiYjkyNGQifQ.eyJqdGkiOiI0NWUxMTFiMC03Njg4LTQ2NDYtYTg5Mi0xOWViNjUzM2JhNTYiLCJleHAiOjE2MTU1MTA1NzIsIm5iZiI6MCwiaWF0IjoxNjEyOTE4NTcyLCJpc3MiOiJodHRwczovL2N0by5haS9hdXRoL3JlYWxtcy9vcHMiLCJhdWQiOiJodHRwczovL2N0by5haS9hdXRoL3JlYWxtcy9vcHMiLCJzdWIiOiJkN2I1NTgxMC0yMzliLTQ4MzctYmQ0ZC0xMjVhNDBjOWExZmMiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoib3BzLWNsaSIsIm5vbmNlIjoiYjJjODJiMzAtNmIzYS0xMWViLWFlZmItZGIwZWFkYzk2ZjJlIiwiYXV0aF90aW1lIjowLCJzZXNzaW9uX3N0YXRlIjoiNDVjZGMxZGYtZjhlYi0hsen66MDD45keFZ4WpoMBdqRySV3R0veviuw1qZSbzk9Uv20hyuX5_-L-oMc3Vn3SxS5xSqOjtTQCyHQK2Mn1Ow0oXA2zHmPJwNY8BMHn54LRxE-iP97cZpnu-VArI8MYc6lCZ2g_eRSb-IycWU8_qhVWsxyPAZgCGQ4tT1yTHO-dckHlFcTIYskXNjcH0n7KgDxbf8TrU9bxIalom31fAJHwpN12gc9s3DPZbmkPa1w5VGT2X8bjFiwl5pwE5yNIeKKQ',
    token_type: 'bearer',
    id_token: jwt.sign({
      jti: 'db34922c-b52e-47b7-8b54-d6a2e8afbc1f',
      nbf: 0,
      iss: `${service}/realms/test`,
      sub: 'd7b55810-239b-4837-bd4d-125a40c9a1fc',
      typ: 'ID',
      azp: 'test-id',
      aud: 'test-id',
      nonce: 'b2c82b30-6b3a-11eb-aefb-db0eadc96f2e',
      session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
      acr: '1',
      email_verified: false,
      name: 'test test',
      preferred_username: 'test',
      given_name: 'test',
      family_name: 'test',
      email: 'test@test.com'
    }, sig, { algorithm: 'RS256', expiresIn: 2592000, header: { kid: 'testkid' } }),
    'not-before-policy': 0,
    session_state: '45cdc1df-f8eb-4470-864d-235196ec09c6',
    scope: 'openid email profile'
  }
  res.end(JSON.stringify(response))
  await certs(server)
  await certs(server)
  await transaction
  server.close()
})

test('error propagation and debug error logging', async ({ is, rejects }) => {
  const until = when()
  const keycloak = await load('..', {
    debug () {
      const debugInst = (err) => {
        is(err.message, 'test')
        until()
      }
      debugInst.enabled = true
      return debugInst
    },
    open () {
      throw Error('test')
    }
  })

  const transaction = rejects(keycloak({
    pages: {
      signup: Buffer.from('signup'), signin: Buffer.from('signin'), error: Buffer.from('error')
    },
    realm: 'test',
    url: 'http://localhost:8080',
    id: 'test-id'
  }).signup())
  await until.done()
  await transaction
})
