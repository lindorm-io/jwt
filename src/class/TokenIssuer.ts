import { Keystore, KeyType } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";
import { TokenError } from "../error";
import { camelKeys, snakeKeys, stringComparison } from "@lindorm-io/core";
import { decode, JsonWebTokenError, NotBeforeError, sign, TokenExpiredError, verify } from "jsonwebtoken";
import { includes } from "lodash";
import { getExpiry, sanitiseToken } from "../util";
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
import { getUnixTime } from "date-fns";

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
    const {
      id = uuid(),
      audience,
      authContextClass,
      authMethodsReference,
      clientId,
      deviceId,
      payload,
      permission,
      scope,
      subject,
    } = options;

    const now = getUnixTime(options.now || new Date());
    const expires = getExpiry(options.expiry);
    const notBefore = getUnixTime(options.notBefore || new Date());
    const expiresIn = expires - now;

    this.logger.debug("signing token", { id, audience, expires, notBefore, now, subject });

    const claims: IssuerClaims = {
      aud: audience,
      exp: expires,
      iat: now,
      iss: this.issuer,
      jti: id,
      nbf: notBefore,
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

  public verify<Payload extends Record<string, any>>(options: IssuerVerifyOptions): IssuerVerifyData<Payload> {
    const { audience, clientId, deviceId, issuer = this.issuer, token } = options;

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
        clockTimestamp: getUnixTime(new Date()),
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

  public static getExpiry(expiry: Expiry): number {
    return getExpiry(expiry);
  }

  public static sanitiseToken(token: string): string {
    return sanitiseToken(token);
  }
}
