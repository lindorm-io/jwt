import MockDate from "mockdate";
import { KeyPair, Keystore } from "@lindorm-io/key-pair";
import { TokenIssuer } from "./TokenIssuer";
import { baseParse } from "@lindorm-io/core";
import { v4 as uuid } from "uuid";
import {
  ExpiredTokenError,
  InactiveTokenError,
  InvalidTokenAudienceError,
  InvalidTokenClientError,
  InvalidTokenIssuerError,
} from "../error";

const RSA_PASSPHRASE = "2e6187af-4b70-4333-aa63-f5fa9f4418ad";

const RSA_PRIVATE_KEY =
  "-----BEGIN RSA PRIVATE KEY-----\n" +
  "Proc-Type: 4,ENCRYPTED\n" +
  "DEK-Info: AES-256-CBC,FCC1524DDB196B41F5DB86218439DE00\n" +
  "\n" +
  "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\n" +
  "-----END RSA PRIVATE KEY-----\n";

const RSA_PUBLIC_KEY =
  "-----BEGIN RSA PUBLIC KEY-----\n" +
  "MIICCgKCAgEAybQm2T+bls/+8+gBZ36r2FGbfytCUjpLT/bRZPsg4W7SEeCVUexh\n" +
  "28UaUyZSTQGxqWbwZR9Tdmh/W5PDjo+P0bORrdbT2pYkDVVlXoODYN1WLswBEuOD\n" +
  "arCsVDhBhpSbo7DkKJrzrQFjdmRjAqd5Ekl4uftqggIP8B5U797PylljmmFe5h7D\n" +
  "wdR19WpOndnDQA1go1rx/qV7Uc9Vgf1Tin5k72G8J/RVT4CJvOs7vV2AF5XXXCQl\n" +
  "+YmDXBKJ10yxqhbCO+6uSPERyZkczGHlaYlzrvB013B78Ll9s+EFatHHttQvzO9p\n" +
  "BUsS5rhcc4aQTA2kSSHF2UoHmKd25kvL8e8xYOhqoYp+7hC3QHKUblh7G5jseUWu\n" +
  "RfkwTv9XPWQPCiYFCFP6rAl88AD8XbkHaGz47X42tzTfqz/j9VTMqSfGwwlIkpCC\n" +
  "I+ssZ2DVlzsKlx2hIFyNMRwSOWRHVwflvDB3smd69wNiwDJjl+0LWydgDl/g3KkC\n" +
  "LpsE/2mU6/EWZTkMgFfp7XAjOuz9hQzuf13uKx/5bjKYTTD7ev8guqlfsSBugDJg\n" +
  "c0VoYkOtd30YENBRdpmE20MNkHnzzFd9bjm4j4ZaIU3xZDe9me/5mInqZuILcl90\n" +
  "GFeCXe7QQ+mEe55+DNs1jV3Z1pZj7eG2hmAJBLSMF7ksee46okGD6D0CAwEAAQ==\n" +
  "-----END RSA PUBLIC KEY-----\n";

const EC_PRIVATE_KEY =
  "-----BEGIN PRIVATE KEY-----\n" +
  "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBGma7xGZpaAngFXf3\n" +
  "mJF3IxZfDpI+6wU564K+eehxX104v6dZetjSfMx0rvsYX/s6cO2P3GE7R95VxWEk\n" +
  "+f4EX0qhgYkDgYYABAB8cBfDwCi41G4kVW4V3Y86nIMMCypYzfO8gYjpS091lxkM\n" +
  "goTRS3LM1p65KQfwBolrWIdVrbbOILASf06fQsHw5gEt4snVuMBO+LS6pesX9vA8\n" +
  "QT1LjX75Xq2InnLY1VToeNmxkuM+oDZgqHOYwzfUhu+zZaA5AuEkqPi47TA9iCSY\n" +
  "VQ==\n" +
  "-----END PRIVATE KEY-----\n";

const EC_PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAfHAXw8AouNRuJFVuFd2POpyDDAsq\n" +
  "WM3zvIGI6UtPdZcZDIKE0UtyzNaeuSkH8AaJa1iHVa22ziCwEn9On0LB8OYBLeLJ\n" +
  "1bjATvi0uqXrF/bwPEE9S41++V6tiJ5y2NVU6HjZsZLjPqA2YKhzmMM31Ibvs2Wg\n" +
  "OQLhJKj4uO0wPYgkmFU=\n" +
  "-----END PUBLIC KEY-----\n";

const ecKey = new KeyPair({
  id: uuid(),
  created: new Date("2020-01-01 08:00:00.000"),
  expires: null,
  algorithm: "ES512",
  type: "ec",
  privateKey: EC_PRIVATE_KEY,
  publicKey: EC_PUBLIC_KEY,
});

const rsaKey = new KeyPair({
  id: uuid(),
  created: new Date("2020-01-01 08:00:00.000"),
  expires: null,
  algorithm: "RS512",
  type: "rsa",
  passphrase: RSA_PASSPHRASE,
  privateKey: RSA_PRIVATE_KEY,
  publicKey: RSA_PUBLIC_KEY,
});

const logger = {
  error: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
};

const parseTokenData = (token: string): any => JSON.parse(baseParse(token.split(".")[1]));

MockDate.set("2020-01-01 09:00:00.000");

describe("TokenIssuer.ts", () => {
  let clientId: any;
  let issuer: any;
  let handler: TokenIssuer;
  let options: any;
  let keystore: any;

  beforeEach(() => {
    clientId = "mock-client-id";
    issuer = "mock-issuer";
    options = {
      audience: "mock-audience",
      authContextClass: "mock-acr",
      authMethodsReference: "mock-amr",
      clientId: "mock-client-id",
      deviceId: "mock-device-id",
      expiry: "10 seconds",
      level: 9001,
      payload: { mock: "mock" },
      permission: "mock-permission",
      scope: "mock-scope",
      subject: "mock-subject",
    };

    keystore = new Keystore({ keys: [ecKey] });
    // @ts-ignore
    handler = new TokenIssuer({ issuer, keystore, logger });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("RS512", () => {
    beforeEach(() => {
      keystore = new Keystore({ keys: [rsaKey] });
      // @ts-ignore
      handler = new TokenIssuer({ issuer, keystore, logger });
    });

    test("should sign/verify", () => {
      const { id, token } = handler.sign(options);
      expect(
        handler.verify({
          audience: options.audience,
          clientId,
          issuer,
          token,
        }),
      ).toStrictEqual({
        id,
        authContextClass: options.authContextClass,
        authMethodsReference: options.authMethodsReference,
        clientId: options.clientId,
        deviceId: options.deviceId,
        level: options.level,
        payload: options.payload,
        permission: options.permission,
        scope: options.scope,
        subject: options.subject,
      });
    });
  });

  describe("ES512", () => {
    beforeEach(() => {
      keystore = new Keystore({ keys: [ecKey] });
      // @ts-ignore
      handler = new TokenIssuer({ issuer, keystore, logger });
    });

    test("should sign/verify", () => {
      const { id, token } = handler.sign(options);
      expect(
        handler.verify({
          audience: options.audience,
          clientId,
          issuer,
          token,
        }),
      ).toStrictEqual({
        id,
        authContextClass: options.authContextClass,
        authMethodsReference: options.authMethodsReference,
        clientId: options.clientId,
        deviceId: options.deviceId,
        level: options.level,
        payload: options.payload,
        permission: options.permission,
        scope: options.scope,
        subject: options.subject,
      });
    });
  });

  test("should create", () => {
    expect(handler.sign(options)).toStrictEqual({
      expires: 1577865610,
      expiresIn: 10,
      id: expect.any(String),
      level: 9001,
      token: expect.any(String),
    });
  });

  test("should decode", () => {
    const { id, token } = handler.sign(options);
    expect(TokenIssuer.decode(token)).toStrictEqual({
      claims: {
        acr: "mock-acr",
        amr: "mock-amr",
        aud: "mock-audience",
        cid: "mock-client-id",
        did: "mock-device-id",
        exp: 1577865610,
        iam: "mock-permission",
        iat: 1577865600,
        iss: "mock-issuer",
        jti: id,
        lvl: 9001,
        nbf: 1577865600,
        payload: {
          mock: "mock",
        },
        scp: "mock-scope",
        sub: "mock-subject",
      },
      keyId: expect.any(String),
    });
  });

  test("should verify", () => {
    const { id, token } = handler.sign(options);
    expect(
      handler.verify({
        audience: options.audience,
        clientId,
        issuer,
        token,
      }),
    ).toStrictEqual({
      id,
      authContextClass: options.authContextClass,
      authMethodsReference: options.authMethodsReference,
      clientId: options.clientId,
      deviceId: options.deviceId,
      level: options.level,
      payload: options.payload,
      permission: options.permission,
      scope: options.scope,
      subject: options.subject,
    });
  });

  test("should return default values", () => {
    const { id, token } = handler.sign({
      audience: "mock-audience",
      expiry: "10 seconds",
      subject: "mock-subject",
    });

    expect(
      handler.verify({
        audience: options.audience,
        issuer,
        token,
      }),
    ).toStrictEqual({
      id,
      authContextClass: null,
      authMethodsReference: null,
      clientId: null,
      deviceId: null,
      level: 0,
      payload: {},
      permission: null,
      scope: null,
      subject: "mock-subject",
    });
  });

  test("should store token payload in snake_case and decode to camelCase", () => {
    const { token } = handler.sign({
      audience: options.audience,
      expiry: "10 seconds",
      subject: options.subject,
      payload: {
        caseOne: 1,
        caseTwo: "two",
        caseThree: { nestedOne: "one", nested_two: 2 },
        case_four: ["array", "data"],
        caseFive: true,
      },
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        payload: {
          case_five: true,
          case_four: ["array", "data"],
          case_one: 1,
          case_three: { nested_one: "one", nested_two: 2 },
          case_two: "two",
        },
      }),
    );

    expect(
      handler.verify({
        audience: options.audience,
        issuer,
        token,
      }),
    ).toStrictEqual(
      expect.objectContaining({
        payload: {
          caseFive: true,
          caseFour: ["array", "data"],
          caseOne: 1,
          caseThree: { nestedOne: "one", nestedTwo: 2 },
          caseTwo: "two",
        },
      }),
    );
  });

  test("should accept string as expiry", () => {
    const { token } = handler.sign({
      id: "mock-id",
      audience: options.audience,
      expiry: "10 seconds",
      subject: options.subject,
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1577865610,
        iat: 1577865600,
        nbf: 1577865600,
      }),
    );
  });

  test("should accept number as expiry", () => {
    const { token } = handler.sign({
      id: "mock-id",
      audience: options.audience,
      expiry: 1577865999,
      subject: options.subject,
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1577865999,
        iat: 1577865600,
        nbf: 1577865600,
      }),
    );
  });

  test("should accept Date as expiry", () => {
    const { token } = handler.sign({
      id: "mock-id",
      audience: options.audience,
      expiry: new Date("2020-12-12 12:00:00"),
      subject: options.subject,
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1607770800,
        iat: 1577865600,
        nbf: 1577865600,
      }),
    );
  });

  test("should reject wrong audience", () => {
    const { token } = handler.sign(options);

    expect(() =>
      handler.verify({
        audience: "wrong audience",
        clientId,
        issuer,
        token,
      }),
    ).toThrowError(expect.any(InvalidTokenAudienceError));
  });

  test("should reject wrong client id", () => {
    const { token } = handler.sign(options);

    expect(() =>
      handler.verify({
        audience: options.audience,
        clientId: "wrong-client-id",
        issuer,
        token,
      }),
    ).toThrowError(expect.any(InvalidTokenClientError));
  });

  test("should reject wrong issuer", () => {
    const { token } = handler.sign(options);

    expect(() =>
      handler.verify({
        audience: options.audience,
        clientId,
        issuer: "wrong-issuer",
        token,
      }),
    ).toThrowError(expect.any(InvalidTokenIssuerError));
  });

  test("should reject an expired token", () => {
    jest.spyOn(global.Date, "now").mockImplementationOnce(() => new Date("1999-01-01T01:01:01.000Z").valueOf());

    const { token } = handler.sign(options);

    expect(() =>
      handler.verify({
        audience: options.audience,
        clientId,
        issuer,
        token,
      }),
    ).toThrowError(expect.any(ExpiredTokenError));
  });

  test("should reject an inactive token", () => {
    const { token } = handler.sign(options);

    jest.spyOn(TokenIssuer, "dateToExpiry").mockImplementationOnce(() => 123456789);

    expect(() =>
      handler.verify({
        audience: options.audience,
        clientId,
        issuer,
        token,
      }),
    ).toThrowError(expect.any(InactiveTokenError));
  });
});
