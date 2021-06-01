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
  aud: string;
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
  payload?: Record<string, any>;
  scope?: string;
}

export interface IssuerSignOptions<Payload> {
  id?: string;
  audience: string;
  authContextClass?: string;
  authMethodsReference?: Array<string>;
  clientId?: string;
  deviceId?: string;
  expiry: Expiry;
  payload?: Payload;
  permission?: string;
  scope?: Array<string>;
  subject: string;
}

export interface IssuerSignData {
  id: string;
  expires: number;
  expiresIn: number;
  token: string;
}

export interface IssuerDecodeData {
  claims: IssuerClaims;
  keyId: string;
}

export interface IssuerVerifyOptions {
  audience: string;
  clientId?: string;
  deviceId?: string;
  issuer?: string;
  token: string;
}

export interface IssuerVerifyData<Payload> {
  id: string;
  authContextClass: string | null;
  authMethodsReference: Array<string> | null;
  clientId: string | null;
  deviceId: string | null;
  payload: Payload;
  permission: string | null;
  scope: Array<string> | null;
  subject: string;
  token: string;
}
