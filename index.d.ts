export = keycloak
declare function keycloak(options: keycloak.Options)

declare namespace keycloak {
  export interface PageBuffers {
    signup: Buffer
    signin: Buffer
    error: Buffer
  }

  export interface Options {
    realm: string
    url: string
    id: string
    pages?: keycloak.PageBuffers
    backend?: boolean
  }

  export interface Tokens {
    accessToken?: string
    idToken?: string
    refreshToken?: string
  }

  export interface Identity {
    id: string
    username: string
    email: string
  }
}

export function validate(tokens: keycloak.Tokens): boolean
export function identity(tokens: keycloak.Tokens): keycloak.Identity
