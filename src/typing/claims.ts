export interface DefaultClaims {
  acr?: string;
  amr?: string;
  aud?: Array<string>;
  exp: number;
  iam?: string;
  iat: number;
  iss: string;
  jti: string;
  nbf: number;
  sub?: string;
}

export interface StandardClaims extends DefaultClaims {
  nonce?: string;
  payload?: Record<string, any>;
  scope?: string;
  token_type: string;
  username?: string;
}
