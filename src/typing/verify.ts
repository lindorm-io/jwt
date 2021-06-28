import { IssuerDecodedClaims } from "./decode";

export interface IssuerVerifyOptions {
  audience: string | Array<string>;
  issuer: string;
  maxAge: string;
  nonce: string;
  scopes: Array<string>;
  subject: string;
  type: string;
}

export interface IssuerVerifyData<Payload, Claims> extends IssuerDecodedClaims<Payload, Claims> {
  token: string;
}
