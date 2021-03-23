import { Keystore } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";

export type TExpiry = string | number | Date;

export interface ITokenIssuerOptions {
  issuer: string;
  keystore: Keystore;
  logger: Logger;
}

export interface ITokenIssuerClaims {
  aud: string;
  exp: number;
  iat: number;
  iss: string;
  jti: string;
  nbf: number;
  sub: string;

  acr?: string;
  amr?: string;
  cid?: string;
  did?: string;
  iam?: string;
  lvl?: number;
  sco?: string;

  payload?: any;
}

export interface ITokenIssuerSignOptions {
  audience: string;
  expiry: TExpiry;
  subject: string;

  id?: string;
  authContextClass?: string;
  authMethodsReference?: string;
  clientId?: string;
  deviceId?: string;
  level?: number;
  payload?: any;
  permission?: string;
  scope?: string;
}

export interface ITokenIssuerSignData {
  id: string;
  expiresIn: number;
  expires: number;
  level: number;
  token: string;
}

export interface ITokenIssuerDecodeData {
  keyId: string;
  claims: ITokenIssuerClaims;
}

export interface ITokenIssuerVerifyOptions {
  audience: string;
  token: string;

  clientId?: string;
  deviceId?: string;
  issuer?: string;
}

export interface ITokenIssuerVerifyData {
  id: string;
  authContextClass: string;
  authMethodsReference: string;
  clientId: string;
  deviceId: string;
  level: number;
  payload: Record<string, any>;
  permission: string;
  scope: string;
  subject: string;
}
