export type Expiry = string | number | Date;

export interface IssuerSignOptions<Payload, Claims> {
  id?: string;
  audience: string | Array<string>;
  authContextClass?: Array<string>;
  authMethodsReference?: Array<string>;
  claims?: Claims;
  expiry: Expiry;
  nonce?: string;
  notBefore?: Date;
  payload?: Payload;
  permission?: string;
  scopes?: Array<string>;
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
