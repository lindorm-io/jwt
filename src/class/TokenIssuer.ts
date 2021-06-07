import { Keystore, KeyType } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";
import { TokenError } from "../error";
import { add, getUnixTime, isBefore, isDate } from "date-fns";
import { camelKeys, snakeKeys, stringComparison, stringToDurationObject } from "@lindorm-io/core";
import { decode, JsonWebTokenError, NotBeforeError, sign, TokenExpiredError, verify } from "jsonwebtoken";
import { includes, isNumber, isString } from "lodash";
import { sanitiseToken } from "../util";
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

  public sign<Payload extends Record<string, any>>({
    id = uuid(),
    audience,
    expiry,
    subject,

    authContextClass,
    authMethodsReference,
    clientId,
    deviceId,
    payload,
    permission,
    scope,
  }: IssuerSignOptions<Payload>): IssuerSignData {
    this.logger.debug("signing token", { id, audience, expiry, subject });

    const now = TokenIssuer.dateToExpiry(new Date());
    const expires = TokenIssuer.getExpiry(expiry);
    const expiresIn = expires - now;

    const claims: IssuerClaims = {
      aud: audience,
      exp: expires,
      iat: now,
      iss: this.issuer,
      jti: id,
      nbf: now,
      sub: subject,
    };

    if (authContextClass) claims.acr = authContextClass;
    if (authMethodsReference) claims.amr = authMethodsReference.join(" ");
    if (clientId) claims.client_id = clientId;
    if (deviceId) claims.device_id = deviceId;
    if (payload) claims.payload = snakeKeys<Payload, Record<string, any>>(payload);
    if (permission) claims.iam = permission;
    if (scope) claims.scope = scope.join(" ");

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
      expires,
      expiresIn,
      token,
    };
  }

  public verify<Payload extends Record<string, any>>({
    audience,
    clientId,
    deviceId,
    issuer = this.issuer,
    token,
  }: IssuerVerifyOptions): IssuerVerifyData<Payload> {
    this.logger.debug("verifying token claims", {
      audience,
      clientId,
      deviceId,
      issuer,
      token: sanitiseToken(token),
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
        audience,
        clockTimestamp: TokenIssuer.dateToExpiry(new Date()),
        issuer,
      });

      if (clientId && claims.client_id && !stringComparison(clientId, claims.client_id)) {
        throw new TokenError("Invalid token", {
          debug: {
            expect: clientId,
            actual: claims.client_id,
          },
          description: "Invalid client ID",
        });
      }

      if (deviceId && claims.device_id && !stringComparison(deviceId, claims.device_id)) {
        throw new TokenError("Invalid token", {
          debug: {
            expect: deviceId,
            actual: claims.device_id,
          },
          description: "Invalid device ID",
        });
      }
    } catch (err) {
      this.logger.error("error verifying token", err);

      if (err instanceof TokenExpiredError) {
        throw new TokenError("Invalid token", {
          error: err,
          description: "Token is expired",
        });
      }

      if (err instanceof NotBeforeError) {
        throw new TokenError("Invalid token", {
          error: err,
          description: "Token is not allowed to be used yet",
        });
      }

      if (includes(err.message, "jwt audience invalid")) {
        throw new TokenError("Invalid token", {
          error: err,
          description: "Token audience is invalid",
        });
      }

      if (includes(err.message, "jwt issuer invalid")) {
        throw new TokenError("Invalid token", {
          error: err,
          description: "Token issuer is invalid",
        });
      }

      if (err instanceof JsonWebTokenError) {
        throw new TokenError("Invalid token", {
          error: err,
          description: "Unable to decode token",
        });
      }

      throw new TokenError("Invalid token", { error: err });
    }

    this.logger.debug("token verified", { token: sanitiseToken(token) });

    return {
      id: claims.jti,
      authContextClass: claims.acr || null,
      authMethodsReference: claims.amr ? claims.amr.split(" ") : null,
      clientId: claims.client_id || null,
      deviceId: claims.device_id || null,
      payload: claims.payload ? camelKeys<Record<string, any>, Payload>(claims.payload) : ({} as Payload),
      permission: claims.iam || null,
      scope: claims.scope ? claims.scope.split(" ") : null,
      subject: claims.sub,
      token,
    };
  }

  public static decode(token: string): IssuerDecodeData {
    const {
      header: { kid: keyId },
      payload: claims,
    }: any = decode(token, { complete: true });

    return { keyId, claims };
  }

  public static expiryToDate(expiry: number): Date {
    return new Date(expiry * 1000);
  }

  public static dateToExpiry(date: Date): number {
    return getUnixTime(date);
  }

  private static getExpiry(expiry: Expiry): number {
    if (isString(expiry)) {
      return TokenIssuer.dateToExpiry(add(Date.now(), stringToDurationObject(expiry)));
    }

    if (isNumber(expiry)) {
      if (isBefore(TokenIssuer.expiryToDate(expiry), new Date())) {
        throw new Error("Invalid token expiry input");
      }

      return expiry;
    }

    if (isDate(expiry)) {
      if (isBefore(expiry, new Date())) {
        throw new Error("Invalid token expiry input");
      }

      return TokenIssuer.dateToExpiry(expiry);
    }

    throw new Error("Invalid token expiry input");
  }
}
