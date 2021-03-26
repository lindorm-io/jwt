import { Keystore } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";

export type TExpiry = string | number | Date;

export interface ITokenIssuerOptions {
  issuer: string;
  keystore: Keystore;
  logger: Logger;
}

export interface ITokenIssuerClaims {
  acr?: string;
  amr?: string;
  aud: string;
  cid?: string;
  did?: string;
  exp: number;
  iam?: string;
  iat: number;
  iss: string;
  jti: string;
  lvl?: number;
  nbf: number;
  payload?: any;
  sco?: string;
  sub: string;
}

export interface ITokenIssuerSignOptions {
  id?: string;
  audience: string;
  authContextClass?: string;
  authMethodsReference?: string;
  clientId?: string;
  deviceId?: string;
  expiry: TExpiry;
  level?: number;
  payload?: any;
  permission?: string;
  scope?: string;
  subject: string;
}

export interface ITokenIssuerSignData {
  id: string;
  expires: number;
  expiresIn: number;
  level: number;
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
  token: string;
}
