import { Keystore, KeyType } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";
import { TokenError } from "../error";
import { camelKeys, snakeKeys, stringComparison } from "@lindorm-io/core";
import { decode, sign, verify } from "jsonwebtoken";
import { getExpiryDate, sanitiseToken } from "../util";
import { getUnixTime } from "date-fns";
import { includes, isString } from "lodash";
import { v4 as uuid } from "uuid";
import {
  Expiry,
  IssuerClaims,
  IssuerDecodeData,
  IssuerOptions,
  IssuerSignData,
  IssuerSignOptions,
  IssuerVerifyData,
  IssuerVerifyOptions,
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

  public sign<Payload extends Record<string, any>>(options: IssuerSignOptions<Payload>): IssuerSignData {
    const id = options.id || uuid();
    const date = new Date();
    const now = getUnixTime(date);
    const expires = getUnixTime(getExpiryDate(options.expiry));
    const notBefore = getUnixTime(options.notBefore || date);
    const expiresIn = expires - now;

    this.logger.debug("signing token", options);

    const claims: IssuerClaims = {
      aud: isString(options.audience) ? [options.audience] : options.audience,
      exp: expires,
      iat: now,
      iss: this.issuer,
      jti: id,
      nbf: notBefore,
      sub: options.subject,
      token_type: options.type,
    };

    if (options.authContextClass) claims.acr = options.authContextClass;
    if (options.authMethodsReference) claims.amr = options.authMethodsReference.join(" ");
    if (options.clientId) claims.client_id = options.clientId;
    if (options.deviceId) claims.device_id = options.deviceId;
    if (options.nonce) claims.nonce = options.nonce;
    if (options.payload) claims.payload = snakeKeys<Payload, Record<string, any>>(options.payload);
    if (options.permission) claims.iam = options.permission;
    if (options.scope) claims.scope = options.scope.join(" ");
    if (options.username) claims.username = options.username;

    this.logger.debug("claims object created", claims);

    const key = this.keystore.getSigningKey();

    const privateKey = key.privateKey as string;
    const signingKey = key.type === KeyType.RSA ? { passphrase: key.passphrase || "", key: privateKey } : privateKey;
    const keyInfo = { algorithm: key.preferredAlgorithm, keyid: key.id };

    this.logger.debug("using key from keystore", keyInfo);

    const token = sign(claims, signingKey, keyInfo);

    this.logger.debug("token signed", { token: sanitiseToken(token) });

    return {
      id,
      expires: getExpiryDate(options.expiry),
      expiresIn,
      token,
    };
  }

  public verify<Payload extends Record<string, any>>(
    token: string,
    options: Partial<IssuerVerifyOptions> = {},
  ): IssuerVerifyData<Payload> {
    this.logger.debug("verifying token claims", {
      token: sanitiseToken(token),
      ...options,
    });

    const { keyId, claims } = TokenIssuer.decode(token);

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

    if (options.clientId && claims.client_id && !stringComparison(options.clientId, claims.client_id)) {
      throw new TokenError("Invalid token", {
        debug: {
          expect: options.clientId,
          actual: claims.client_id,
        },
        description: "Invalid client identifier",
      });
    }

    if (options.deviceId && claims.device_id && !stringComparison(options.deviceId, claims.device_id)) {
      throw new TokenError("Invalid token", {
        debug: {
          expect: options.deviceId,
          actual: claims.device_id,
        },
        description: "Invalid device identifier",
      });
    }

    if (options.scope) {
      if (!claims.scope?.length) {
        throw new TokenError("Invalid token", {
          debug: {
            expect: options.scope,
            actual: claims.scope,
          },
          description: "Scope claim not found on token",
        });
      }

      for (const scope of options.scope) {
        if (includes(claims.scope, scope)) continue;

        throw new TokenError("Invalid token", {
          data: { scope },
          debug: {
            expect: options.scope,
            actual: claims.scope,
          },
          description: "Expected scope not found",
        });
      }
    }

    if (options.type && claims.token_type && !stringComparison(options.type, claims.token_type)) {
      throw new TokenError("Invalid token", {
        debug: {
          expect: options.type,
          actual: claims.token_type,
        },
        description: "Invalid token type",
      });
    }

    this.logger.debug("token verified", { token: sanitiseToken(token) });

    return {
      id: claims.jti,
      audience: claims.aud,
      authContextClass: claims.acr || null,
      authMethodsReference: claims.amr ? claims.amr.split(" ") : null,
      clientId: claims.client_id || null,
      deviceId: claims.device_id || null,
      nonce: claims.nonce || null,
      payload: claims.payload ? camelKeys<Record<string, any>, Payload>(claims.payload) : ({} as Payload),
      permission: claims.iam || null,
      scope: claims.scope ? claims.scope.split(" ") : null,
      subject: claims.sub,
      token,
      type: claims.token_type,
      username: claims.username || null,
    };
  }

  public static decode(token: string): IssuerDecodeData {
    const {
      header: { kid: keyId },
      payload: claims,
    }: any = decode(token, { complete: true });

    return { keyId, claims };
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
