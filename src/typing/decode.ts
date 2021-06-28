export interface IssuerDecodedClaims<Payload, Claims> {
  id: string;
  audience: Array<string>;
  authContextClass: Array<string>;
  authMethodsReference: Array<string>;
  nonce: string | null;
  payload: Payload;
  permission: string | null;
  scopes: Array<string>;
  subject: string | null;
  type: string;
  username: string | null;
  claims: Claims;
}

export interface IssuerDecodeData<Payload, Claims> extends IssuerDecodedClaims<Payload, Claims> {
  keyId: string;
}
