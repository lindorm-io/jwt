import { Keystore } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";

export type TExpiry = string | number | Date;

export interface ITokenIssuerOptions {
  issuer: string;
  keystore: Keystore;
  logger: Logger;
}

export interface IDefaultClaims {
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

export interface ITokenIssuerClaims extends IDefaultClaims {
  client_id?: string;
  device_id?: string;
  payload?: Record<string, any>;
  scope?: string;
}

export interface ITokenIssuerSignOptions<Payload> {
  id?: string;
  audience: string;
  authContextClass?: string;
  authMethodsReference?: Array<string>;
  clientId?: string;
  deviceId?: string;
  expiry: TExpiry;
  payload?: Payload;
  permission?: string;
  scope?: Array<string>;
  subject: string;
}

export interface ITokenIssuerSignData {
  id: string;
  expires: number;
  expiresIn: number;
  token: string;
}

export interface ITokenIssuerDecodeData {
  claims: ITokenIssuerClaims;
  keyId: string;
}

export interface ITokenIssuerVerifyOptions {
  audience: string;
  clientId?: string;
  deviceId?: string;
  issuer?: string;
  token: string;
}

export interface ITokenIssuerVerifyData<Payload> {
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
