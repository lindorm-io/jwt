import { Keystore } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";

export type Expiry = string | number | Date;

export interface IssuerOptions {
  issuer: string;
  keystore: Keystore;
  logger: Logger;
}

export interface DefaultClaims {
  acr?: string;
  amr?: string;
  aud: Array<string>;
  exp: number;
  iam?: string;
  iat: number;
  iss: string;
  jti: string;
  nbf: number;
  sub: string;
}

export interface IssuerClaims extends DefaultClaims {
  client_id?: string;
  device_id?: string;
  nonce?: string;
  payload?: Record<string, any>;
  scope?: string;
  token_type: string;
  username?: string;
}

export interface IssuerSignOptions<Payload> {
  id?: string;
  audience: string | Array<string>;
  authContextClass?: string;
  authMethodsReference?: Array<string>;
  clientId?: string;
  deviceId?: string;
  expiry: Expiry;
  nonce?: string;
  notBefore?: Date;
  payload?: Payload;
  permission?: string;
  scope?: Array<string>;
  subject: string;
  type: string;
  username?: string;
}

export interface IssuerSignData {
  id: string;
  expires: Date;
  expiresIn: number;
  token: string;
}

export interface IssuerDecodeData {
  claims: IssuerClaims;
  keyId: string;
}

export interface IssuerVerifyOptions {
  audience: string | Array<string>;
  clientId: string;
  deviceId: string;
  issuer: string;
  maxAge: string;
  nonce: string;
  scope: Array<string>;
  subject: string;
  type: string;
}

export interface IssuerVerifyData<Payload> {
  id: string;
  audience: Array<string>;
  authContextClass: string | null;
  authMethodsReference: Array<string> | null;
  clientId: string | null;
  deviceId: string | null;
  nonce: string | null;
  payload: Payload;
  permission: string | null;
  scope: Array<string> | null;
  subject: string;
  token: string;
  type: string;
  username: string | null;
}
