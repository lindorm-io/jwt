import { Keystore, KeyType } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";
import { TokenError } from "../error";
import { camelKeys, snakeKeys, sortObjectKeys } from "@lindorm-io/core";
import { decode, sign, verify } from "jsonwebtoken";
import { difference, isArray, isString } from "lodash";
import { getExpiryDate, sanitiseToken } from "../util";
import { getUnixTime } from "date-fns";
import { v4 as uuid } from "uuid";
import {
  Expiry,
  IssuerDecodeData,
  IssuerOptions,
  IssuerSignData,
  IssuerSignOptions,
  IssuerVerifyData,
  IssuerVerifyOptions,
  StandardClaims,
} from "../typing";

export class TokenIssuer {
  private readonly issuer: string;
  private readonly keystore: Keystore;
  private readonly logger: Logger;

  public constructor(options: IssuerOptions) {
    this.issuer = options.issuer;
    this.keystore = options.keystore;
    this.logger = options.logger.createChildLogger("TokenIssuer");
  }

  public sign<
    Payload extends Record<string, any> = Record<string, any>,
    Claims extends Record<string, any> = Record<string, any>,
  >(options: IssuerSignOptions<Payload, Claims>): IssuerSignData {
    const id = options.id || uuid();
    const date = new Date();
    const now = getUnixTime(date);
    const expires = getUnixTime(getExpiryDate(options.expiry));
    const notBefore = getUnixTime(options.notBefore || date);
    const expiresIn = expires - now;

    this.logger.debug("signing token", options);

    const object: StandardClaims = {
      exp: expires,
      iat: now,
      iss: this.issuer,
      jti: id,
      nbf: notBefore,
      token_type: options.type,
      ...(options.claims ? snakeKeys(options.claims) : {}),
    };

    if (options.audience) object.aud = isString(options.audience) ? [options.audience] : options.audience;
    if (options.authContextClass) object.acr = options.authContextClass.join(" ");
    if (options.authMethodsReference) object.amr = options.authMethodsReference.join(" ");
    if (options.nonce) object.nonce = options.nonce;
    if (options.payload) object.payload = snakeKeys<Payload, Record<string, any>>(options.payload);
    if (options.permission) object.iam = options.permission;
    if (options.scopes) object.scope = options.scopes.join(" ");
    if (options.subject) object.sub = options.subject;
    if (options.username) object.username = options.username;

    this.logger.debug("claims object created", object);

    const key = this.keystore.getSigningKey();

    const privateKey = key.privateKey as string;
    const signingKey = key.type === KeyType.RSA ? { passphrase: key.passphrase || "", key: privateKey } : privateKey;
    const keyInfo = { algorithm: key.preferredAlgorithm, keyid: key.id };

    this.logger.debug("using key from keystore", keyInfo);

    const token = sign(sortObjectKeys(object), signingKey, keyInfo);

    this.logger.debug("token signed", { token: sanitiseToken(token) });

    return {
      id,
      expires: getExpiryDate(options.expiry),
      expiresIn,
      token,
    };
  }

  public verify<
    Payload extends Record<string, any> = Record<string, any>,
    Claims extends Record<string, any> = Record<string, any>,
  >(token: string, options: Partial<IssuerVerifyOptions> = {}): IssuerVerifyData<Payload, Claims> {
    this.logger.debug("verifying token claims", {
      token: sanitiseToken(token),
      ...options,
    });

    const { keyId, ...claims } = TokenIssuer.decode<Payload, Claims>(token);

    const key = this.keystore.getKey(keyId);

    this.logger.debug("decoded key info", {
      algorithms: key.algorithms,
      keyid: key.id,
    });

    try {
      verify(token, key.publicKey, {
        algorithms: key.algorithms,
        audience: options.audience,
        clockTimestamp: getUnixTime(new Date()),
        issuer: options.issuer || this.issuer,
        maxAge: options.maxAge,
        nonce: options.nonce,
        subject: options.subject,
      });
    } catch (err) {
      throw new TokenError("Invalid token", { error: err });
    }

    if (isArray(options.scopes)) {
      if (!claims.scopes?.length) {
        throw new TokenError("Invalid token", {
          debug: {
            expect: options.scopes,
            actual: claims.scopes,
          },
          description: "Scope claim not found on token",
        });
      }

      const diff = difference(options.scopes, claims.scopes);

      if (diff.length) {
        throw new TokenError("Invalid token", {
          debug: {
            expect: options.scopes,
            actual: claims.scopes,
            diff,
          },
          description: "Expected scope not found",
        });
      }
    }

    if (options.type && claims.type && options.type !== claims.type) {
      throw new TokenError("Invalid token", {
        debug: {
          expect: options.type,
          actual: claims.type,
        },
        description: "Invalid token type",
      });
    }

    this.logger.debug("token verified", { token: sanitiseToken(token) });

    return {
      token,
      ...claims,
    };
  }

  public static decode<
    Payload extends Record<string, any> = Record<string, any>,
    Claims extends Record<string, any> = Record<string, any>,
  >(token: string): IssuerDecodeData<Payload, Claims> {
    const {
      header: { kid: keyId },
      payload: object,
    }: any = decode(token, { complete: true });

    const { acr, amr, aud, exp, iam, iat, iss, jti, nbf, nonce, payload, scope, sub, token_type, username, ...claims } =
      object;

    return {
      id: jti,
      audience: aud || [],
      authContextClass: acr ? acr.split(" ") : [],
      authMethodsReference: amr ? amr.split(" ") : [],
      claims: claims ? camelKeys<Record<string, unknown>, Claims>(claims) : ({} as Claims),
      keyId,
      nonce: nonce || null,
      payload: payload ? camelKeys<Record<string, unknown>, Payload>(payload) : ({} as Payload),
      permission: iam || null,
      scopes: scope ? scope.split(" ") : [],
      subject: sub || null,
      type: token_type,
      username: username || null,
    };
  }

  public static getExpiry(expiry: Expiry): number {
    return getUnixTime(getExpiryDate(expiry));
  }

  public static getExpiryDate(expiry: Expiry): Date {
    return getExpiryDate(expiry);
  }

  public static getUnixTime(date: Date): number {
    return getUnixTime(date);
  }

  public static sanitiseToken(token: string): string {
    return sanitiseToken(token);
  }
}
