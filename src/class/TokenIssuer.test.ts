import MockDate from "mockdate";
import { Keystore } from "@lindorm-io/key-pair";
import { TokenIssuer } from "./TokenIssuer";
import { baseParse } from "@lindorm-io/core";
import { getTestKeyPairEC, getTestKeyPairRSA, logger } from "../test";
import { TokenError } from "../error";

const parseTokenData = (token: string): any => JSON.parse(baseParse(token.split(".")[1]));

MockDate.set("2020-01-01T08:00:00.000Z");

describe("TokenIssuer", () => {
  let clientId: any;
  let issuer: any;
  let handler: TokenIssuer;
  let options: any;

  beforeEach(() => {
    clientId = "mock-client-id";
    issuer = "mock-issuer";
    options = {
      id: "d2457602-63bd-48c5-a19f-bfd81bf870c0",
      audience: "mock-audience",
      authContextClass: "mock-acr",
      authMethodsReference: ["mock-amr"],
      clientId: "mock-client-id",
      deviceId: "mock-device-id",
      expiry: "10 seconds",
      payload: { mock: "mock" },
      permission: "mock-permission",
      scope: ["mock-scope"],
      subject: "mock-subject",
    };

    handler = new TokenIssuer({
      issuer,
      keystore: new Keystore({ keys: [getTestKeyPairEC()] }),
      logger,
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("RS512", () => {
    beforeEach(() => {
      handler = new TokenIssuer({
        issuer,
        keystore: new Keystore({ keys: [getTestKeyPairRSA()] }),
        logger,
      });
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
        id: id,
        authContextClass: options.authContextClass,
        authMethodsReference: options.authMethodsReference,
        clientId: options.clientId,
        deviceId: options.deviceId,
        payload: options.payload,
        permission: options.permission,
        scope: options.scope,
        subject: options.subject,
        token: token,
      });
    });
  });

  describe("ES512", () => {
    beforeEach(() => {
      handler = new TokenIssuer({
        issuer,
        keystore: new Keystore({ keys: [getTestKeyPairEC()] }),
        logger,
      });
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
        id: id,
        authContextClass: options.authContextClass,
        authMethodsReference: options.authMethodsReference,
        clientId: options.clientId,
        deviceId: options.deviceId,
        payload: options.payload,
        permission: options.permission,
        scope: options.scope,
        subject: options.subject,
        token: token,
      });
    });
  });

  test("should create", () => {
    expect(handler.sign(options)).toStrictEqual({
      expires: 1577865610,
      expiresIn: 10,
      id: expect.any(String),
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
        client_id: "mock-client-id",
        device_id: "mock-device-id",
        exp: 1577865610,
        iam: "mock-permission",
        iat: 1577865600,
        iss: "mock-issuer",
        jti: id,
        nbf: 1577865600,
        payload: {
          mock: "mock",
        },
        scope: "mock-scope",
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
      id: id,
      authContextClass: options.authContextClass,
      authMethodsReference: options.authMethodsReference,
      clientId: options.clientId,
      deviceId: options.deviceId,
      payload: options.payload,
      permission: options.permission,
      scope: options.scope,
      subject: options.subject,
      token: token,
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
      id: id,
      authContextClass: null,
      authMethodsReference: null,
      clientId: null,
      deviceId: null,
      payload: {},
      permission: null,
      scope: null,
      subject: "mock-subject",
      token: token,
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
        exp: 1607774400,
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
    ).toThrow(TokenError);
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
    ).toThrow(TokenError);
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
    ).toThrow(TokenError);
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
    ).toThrow(TokenError);
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
    ).toThrow(TokenError);
  });
});
