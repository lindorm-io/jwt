import { Keystore } from "@lindorm-io/key-pair";
import { Logger } from "@lindorm-io/winston";
import { TObject } from "@lindorm-io/global";
import { add, getUnixTime, isBefore, isDate } from "date-fns";
import { camelKeys, snakeKeys, stringComparison, stringToDurationObject } from "@lindorm-io/common";
import { decode, sign, verify, Algorithm, JsonWebTokenError, NotBeforeError, TokenExpiredError } from "jsonwebtoken";
import { isNumber, isString, includes } from "lodash";
import { sanitiseToken } from "../util";
import { v4 as uuid } from "uuid";
import {
  DecodeTokenError,
  ExpiredTokenError,
  InactiveTokenError,
  InvalidTokenAudienceError,
  InvalidTokenClientError,
  InvalidTokenDeviceError,
  InvalidTokenExpiryInput,
  InvalidTokenIssuerError,
} from "../error";

export type TExpiry = string | number | Date;

export interface ITokenIssuerOptions {
  issuer: string;
  keystore: Keystore;
  logger: Logger;
}

export interface IClaims {
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
  scp?: string;

  payload?: any;
}

export interface ISignOptions {
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

export interface ISignData {
  id: string;
  expiresIn: number;
  expires: number;
  level: number;
  token: string;
}

export interface IVerifyOptions {
  audience: string;
  token: string;

  clientId?: string;
  deviceId?: string;
  issuer?: string;
}

export interface IVerifyData {
  id: string;
  authContextClass: string;
  authMethodsReference: string;
  clientId: string;
  deviceId: string;
  level: number;
  payload: TObject<any>;
  permission: string;
  scope: string;
  subject: string;
}

export class TokenIssuer {
  private issuer: string;
  private keystore: Keystore;
  private logger: Logger;

  constructor(options: ITokenIssuerOptions) {
    this.issuer = options.issuer;
    this.keystore = options.keystore;
    this.logger = options.logger;
  }

  public sign(options: ISignOptions): ISignData {
    this.logger.debug("sign token", options);

    const {
      id = uuid(),
      audience,
      expiry,
      subject,

      authContextClass,
      authMethodsReference,
      clientId,
      deviceId,
      level,
      payload,
      permission,
      scope,
    } = options;

    const now = TokenIssuer.dateToExpiry(new Date());
    const expires = TokenIssuer.getExpiry(expiry);
    const expiresIn = expires - now;

    this.logger.debug("creating claims object");

    const claims: IClaims = {
      aud: audience,
      exp: expires,
      iat: now,
      iss: this.issuer,
      jti: id,
      nbf: now,
      sub: subject,
    };

    if (authContextClass) {
      claims.acr = authContextClass;
    }
    if (authMethodsReference) {
      claims.amr = authMethodsReference;
    }
    if (clientId) {
      claims.cid = clientId;
    }
    if (deviceId) {
      claims.did = deviceId;
    }
    if (permission) {
      claims.iam = permission;
    }
    if (level) {
      claims.lvl = level;
    }
    if (scope) {
      claims.scp = scope;
    }
    if (payload) {
      claims.payload = snakeKeys(payload);
    }

    this.logger.debug("using keystore to find key");

    const key = this.keystore.getCurrentKey();
    const privateKey = key.passphrase ? { passphrase: key.passphrase, key: key.privateKey } : key.privateKey;
    const algorithm: unknown = key.algorithm;
    const keyInfo = { algorithm: algorithm as Algorithm, keyid: key.id };

    const token = sign(claims, privateKey, keyInfo);

    this.logger.info("token signed", {
      claims,
      key: { id: key.id, algorithm: key.algorithm },
      token: sanitiseToken(token),
    });

    return {
      id,
      expires,
      expiresIn,
      level,
      token,
    };
  }

  public verify(options: IVerifyOptions): IVerifyData {
    const data = this.decode(options);

    return {
      id: data.jti,
      authContextClass: data.acr || "",
      authMethodsReference: data.amr || "",
      clientId: data.cid || "",
      deviceId: data.did || "",
      level: data.lvl || 0,
      payload: data.payload ? camelKeys(data.payload) : {},
      permission: data.iam || "",
      scope: data.scp || "",
      subject: data.sub,
    };
  }

  public static expiryToDate(expiry: number): Date {
    return new Date(expiry * 1000);
  }

  public static dateToExpiry(date: Date): number {
    return getUnixTime(date);
  }

  private decode(options: IVerifyOptions): IClaims {
    options.issuer = options.issuer || this.issuer;

    const { audience, clientId, deviceId, issuer, token } = options;

    this.logger.info("decode token", {
      audience,
      clientId,
      deviceId,
      issuer,
      token: sanitiseToken(token),
    });

    const {
      header: { kid: keyId },
      payload: decoded,
    }: any = decode(token, { complete: true });

    const key = this.keystore.getKey(keyId);
    const algorithm: unknown = key.algorithm;

    this.logger.debug("verifying token", {
      key: { id: key.id, algorithm: key.algorithm },
    });

    try {
      verify(token, key.publicKey, {
        algorithms: [algorithm as Algorithm],
        audience,
        clockTimestamp: TokenIssuer.dateToExpiry(new Date()),
        issuer,
      });
    } catch (err) {
      this.logger.error(err);

      if (err instanceof TokenExpiredError) {
        throw new ExpiredTokenError(err);
      }

      if (err instanceof NotBeforeError) {
        throw new InactiveTokenError(err);
      }

      if (includes(err.message, "jwt audience invalid")) {
        throw new InvalidTokenAudienceError(err, audience);
      }

      if (includes(err.message, "jwt issuer invalid")) {
        throw new InvalidTokenIssuerError(err, issuer);
      }

      if (err instanceof JsonWebTokenError) {
        throw new DecodeTokenError(err);
      }

      throw err;
    }

    if (clientId && !stringComparison(clientId, decoded.cid)) {
      throw new InvalidTokenClientError(clientId, decoded.cid);
    }

    if (deviceId && !stringComparison(deviceId, decoded.did)) {
      throw new InvalidTokenDeviceError(deviceId, decoded.did);
    }

    return decoded;
  }

  private static getExpiry(expiry: TExpiry): number {
    if (isString(expiry)) {
      return TokenIssuer.dateToExpiry(add(Date.now(), stringToDurationObject(expiry)));
    }

    if (isNumber(expiry)) {
      if (isBefore(TokenIssuer.expiryToDate(expiry), new Date())) {
        throw new InvalidTokenExpiryInput(expiry);
      }

      return expiry;
    }

    if (isDate(expiry)) {
      if (isBefore(expiry, new Date())) {
        throw new InvalidTokenExpiryInput(expiry);
      }

      return TokenIssuer.dateToExpiry(expiry);
    }

    throw new InvalidTokenExpiryInput(expiry);
  }
}
