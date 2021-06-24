import MockDate from "mockdate";
import { Keystore } from "@lindorm-io/key-pair";
import { TokenIssuer } from "./TokenIssuer";
import { baseParse } from "@lindorm-io/core";
import { getTestKeyPairEC, getTestKeyPairRSA, logger } from "../test";
import { TokenError } from "../error";

const parseTokenData = (token: string): any => JSON.parse(baseParse(token.split(".")[1]));

MockDate.set("2021-01-01T08:00:00.000Z");

describe("TokenIssuer", () => {
  let clientId: any;
  let handler: TokenIssuer;
  let issuer: any;
  let options: any;

  beforeEach(() => {
    clientId = "d7f8a289-dc1b-41eb-ae97-56eb1c2a1c84";
    issuer = "issuer";
    options = {
      id: "d2457602-63bd-48c5-a19f-bfd81bf870c0",
      audience: ["audience"],
      authContextClass: "acr",
      authMethodsReference: ["amr"],
      clientId: "d7f8a289-dc1b-41eb-ae97-56eb1c2a1c84",
      deviceId: "6f08189c-56d1-468c-892b-ba0ae1d83e0f",
      expiry: "10 seconds",
      nonce: "bed190d568a5456bb15a39cf71d72022",
      notBefore: new Date(),
      payload: { mock: "mock" },
      permission: "permission",
      scope: ["scope"],
      subject: "subject",
      type: "type",
      username: "username",
    };

    handler = new TokenIssuer({
      issuer,
      keystore: new Keystore({ keys: [getTestKeyPairEC()] }),
      logger,
    });
  });

  afterEach(jest.clearAllMocks);

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

      expect(handler.verify(token)).toStrictEqual({
        id,
        audience: ["audience"],
        authContextClass: "acr",
        authMethodsReference: ["amr"],
        clientId: "d7f8a289-dc1b-41eb-ae97-56eb1c2a1c84",
        deviceId: "6f08189c-56d1-468c-892b-ba0ae1d83e0f",
        nonce: "bed190d568a5456bb15a39cf71d72022",
        payload: { mock: "mock" },
        permission: "permission",
        scope: ["scope"],
        subject: "subject",
        token: expect.any(String),
        type: "type",
        username: "username",
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

      expect(handler.verify(token)).toStrictEqual({
        id,
        audience: ["audience"],
        authContextClass: "acr",
        authMethodsReference: ["amr"],
        clientId: "d7f8a289-dc1b-41eb-ae97-56eb1c2a1c84",
        deviceId: "6f08189c-56d1-468c-892b-ba0ae1d83e0f",
        nonce: "bed190d568a5456bb15a39cf71d72022",
        payload: { mock: "mock" },
        permission: "permission",
        scope: ["scope"],
        subject: "subject",
        token: expect.any(String),
        type: "type",
        username: "username",
      });
    });
  });

  test("should create", () => {
    expect(handler.sign(options)).toStrictEqual({
      id: expect.any(String),
      expires: expect.any(Date),
      expiresIn: 10,
      token: expect.any(String),
    });
  });

  test("should decode", () => {
    const { id, token } = handler.sign(options);

    expect(TokenIssuer.decode(token)).toStrictEqual({
      claims: {
        acr: "acr",
        amr: "amr",
        aud: ["audience"],
        client_id: "d7f8a289-dc1b-41eb-ae97-56eb1c2a1c84",
        device_id: "6f08189c-56d1-468c-892b-ba0ae1d83e0f",
        exp: 1609488010,
        iam: "permission",
        iat: 1609488000,
        iss: "issuer",
        jti: id,
        token_type: "type",
        nbf: 1609488000,
        nonce: "bed190d568a5456bb15a39cf71d72022",
        payload: {
          mock: "mock",
        },
        scope: "scope",
        sub: "subject",
        username: "username",
      },
      keyId: "7531da89-12e9-403e-925a-5da49100635c",
    });
  });

  test("should verify", () => {
    const { token } = handler.sign(options);

    expect(
      handler.verify(token, {
        audience: options.audience,
        clientId,
        deviceId: options.deviceId,
        issuer,
        nonce: options.nonce,
        scope: ["scope"],
      }),
    ).toBeTruthy();
  });

  test("should return all signed values", () => {
    const { id, token } = handler.sign(options);

    expect(handler.verify(token)).toStrictEqual({
      id,
      audience: ["audience"],
      authContextClass: "acr",
      authMethodsReference: ["amr"],
      clientId: "d7f8a289-dc1b-41eb-ae97-56eb1c2a1c84",
      deviceId: "6f08189c-56d1-468c-892b-ba0ae1d83e0f",
      nonce: "bed190d568a5456bb15a39cf71d72022",
      payload: { mock: "mock" },
      permission: "permission",
      scope: ["scope"],
      subject: "subject",
      token: expect.any(String),
      type: "type",
      username: "username",
    });
  });

  test("should return default values", () => {
    const { id, token } = handler.sign({
      audience: ["audience"],
      expiry: "10 seconds",
      subject: "subject",
      type: "type",
    });

    expect(handler.verify(token)).toStrictEqual({
      id: id,
      audience: ["audience"],
      authContextClass: null,
      authMethodsReference: null,
      clientId: null,
      deviceId: null,
      nonce: null,
      payload: {},
      permission: null,
      scope: null,
      subject: "subject",
      token: token,
      type: "type",
      username: null,
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
      type: "type",
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

    expect(handler.verify(token)).toStrictEqual(
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
      audience: options.audience,
      expiry: "10 seconds",
      subject: options.subject,
      type: "type",
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1609488010,
        iat: 1609488000,
        nbf: 1609488000,
      }),
    );
  });

  test("should accept number as expiry", () => {
    const { token } = handler.sign({
      audience: options.audience,
      expiry: 1609488010,
      subject: options.subject,
      type: "type",
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1609488010,
        iat: 1609488000,
        nbf: 1609488000,
      }),
    );
  });

  test("should accept Date as expiry", () => {
    const { token } = handler.sign({
      audience: options.audience,
      expiry: new Date("2021-12-12 12:00:00"),
      subject: options.subject,
      type: "type",
    });

    const data = parseTokenData(token);

    expect(data).toStrictEqual(
      expect.objectContaining({
        exp: 1639310400,
        iat: 1609488000,
        nbf: 1609488000,
      }),
    );
  });

  test("should reject invalid client id", () => {
    const { token } = handler.sign(options);

    expect(() =>
      handler.verify(token, {
        clientId: "434c382e-bc9c-4dca-8672-55a7b9026250",
      }),
    ).toThrow(TokenError);
  });

  test("should reject invalid device id", () => {
    const { token } = handler.sign(options);

    expect(() =>
      handler.verify(token, {
        deviceId: "434c382e-bc9c-4dca-8672-55a7b9026250",
      }),
    ).toThrow(TokenError);
  });

  test("should reject missing scope", () => {
    const { token } = handler.sign({ ...options, scope: [] });

    expect(() =>
      handler.verify(token, {
        scope: ["unexpected"],
      }),
    ).toThrow(TokenError);
  });

  test("should reject invalid scope", () => {
    const { token } = handler.sign(options);

    expect(() =>
      handler.verify(token, {
        scope: ["unexpected"],
      }),
    ).toThrow(TokenError);
  });

  test("should reject invalid type", () => {
    const { token } = handler.sign(options);

    expect(() =>
      handler.verify(token, {
        type: "wrong-type",
      }),
    ).toThrow(TokenError);
  });

  test("should reject expired", () => {
    const { token } = handler.sign({
      ...options,
      expiry: new Date("2021-01-01T08:10:00.000Z"),
    });

    MockDate.set("2022-01-01T08:10:00.000Z");

    expect(() => handler.verify(token)).toThrow(TokenError);

    MockDate.set("2021-01-01T08:00:00.000Z");
  });

  test("should reject token not yet valid", () => {
    const { token } = handler.sign({
      ...options,
      notBefore: new Date("2021-01-01T09:00:00.000Z"),
      expiry: new Date("2021-01-01T10:00:00.000Z"),
    });

    MockDate.set("2022-01-01T08:30:00.000Z");

    expect(() => handler.verify(token)).toThrow(TokenError);

    MockDate.set("2021-01-01T08:00:00.000Z");
  });
});
